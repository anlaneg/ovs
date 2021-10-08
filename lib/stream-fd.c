/*
 * Copyright (c) 2008, 2009, 2010, 2012, 2013, 2014, 2015 Nicira, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>
#include "stream-fd.h"
#include <errno.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include "fatal-signal.h"
#include "openvswitch/poll-loop.h"
#include "socket-util.h"
#include "util.h"
#include "stream-provider.h"
#include "stream.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(stream_fd);
//定义了主动，被动两种，主动可以看起是client fd，被动是server fd
//client fd可以进行read,write
//server fd可以进行accept，accept会接入一个新的stream_fd做为client fd和客户端的stream-fd进行read,write

/* Active file descriptor stream. */

struct stream_fd
{
    struct stream stream;
    int fd;/*描述符*/
    int fd_type;//fd类型，例如AF_INET
};

static const struct stream_class stream_fd_class;

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(10, 25);

static void maybe_unlink_and_free(char *path);

/* Creates a new stream named 'name' that will send and receive data on 'fd'
 * and stores a pointer to the stream in '*streamp'.  Initial connection status
 * 'connect_status' is interpreted as described for stream_init(). 'fd_type'
 * tells whether the socket is TCP or Unix domain socket.
 *
 * Takes ownership of 'name'.
 *
 * Returns 0 if successful, otherwise a positive errno value.  (The current
 * implementation never fails.) */
int
new_fd_stream(char *name, int fd, int connect_status, int fd_type,
              struct stream **streamp)
{
    struct stream_fd *s;

    s = xmalloc(sizeof *s);
    //使用stream_fd_class
    stream_init(&s->stream, &stream_fd_class, connect_status, name);
    s->fd = fd;
    s->fd_type = fd_type;
    *streamp = &s->stream;
    return 0;
}

static struct stream_fd *
stream_fd_cast(struct stream *stream)
{
    stream_assert_class(stream, &stream_fd_class);
    return CONTAINER_OF(stream, struct stream_fd, stream);
}

//关闭fd，并释放结构
static void
fd_close(struct stream *stream)
{
    struct stream_fd *s = stream_fd_cast(stream);
    closesocket(s->fd);
    free(s);
}

static int
fd_connect(struct stream *stream)//检查fd是否可写，返回0成功，否则返回errno
{
    struct stream_fd *s = stream_fd_cast(stream);
    int retval = check_connection_completion(s->fd);
    if (retval == 0 && s->fd_type == AF_INET) {
        setsockopt_tcp_nodelay(s->fd);
    }
    return retval;
}

static ssize_t
fd_recv(struct stream *stream, void *buffer, size_t n)//收取n字节，填充到buffer中
{
    struct stream_fd *s = stream_fd_cast(stream);
    ssize_t retval;
    int error;

    retval = recv(s->fd, buffer, n, 0);
    if (retval < 0) {
        error = sock_errno();
#ifdef _WIN32
        if (error == WSAEWOULDBLOCK) {
           error = EAGAIN;
        }
#endif
        if (error != EAGAIN) {
            VLOG_DBG_RL(&rl, "recv: %s", sock_strerror(error));
        }
        return -error;
    }
    return retval;
}

static ssize_t
fd_send(struct stream *stream, const void *buffer, size_t n)//发送buffer中的内容，长度为n
{
    struct stream_fd *s = stream_fd_cast(stream);
    ssize_t retval;
    int error;

    retval = send(s->fd, buffer, n, 0);
    if (retval < 0) {
        error = sock_errno();
#ifdef _WIN32
        if (error == WSAEWOULDBLOCK) {
           error = EAGAIN;
        }
#endif
        if (error != EAGAIN) {
            VLOG_DBG_RL(&rl, "send: %s", sock_strerror(error));
        }
        return -error;
    }
    return (retval > 0 ? retval : -EAGAIN);
}

//按等待类型，创建期待可读或可写的poll_node
static void
fd_wait(struct stream *stream, enum stream_wait_type wait)
{
    struct stream_fd *s = stream_fd_cast(stream);
    switch (wait) {
    case STREAM_CONNECT:
    case STREAM_SEND:
        poll_fd_wait(s->fd, POLLOUT);//创建write事件
        break;

    case STREAM_RECV:
        poll_fd_wait(s->fd, POLLIN);//创建read事件
        break;

    default:
        OVS_NOT_REACHED();
    }
}

static const struct stream_class stream_fd_class = {
    "fd",                       /* name */
    false,                      /* needs_probes */
    NULL,                       /* open */ //打开后关联的，故open不需要处理
    fd_close,                   /* close */ //关闭
    fd_connect,                 /* connect */
    fd_recv,                    /* recv */ //收取
    fd_send,                    /* send */ //发送
    NULL,                       /* run */
    NULL,                       /* run_wait */
    fd_wait,                    /* wait */ //将fd加入到poll_node,期待相应的读写事件
};

/* Passive file descriptor stream. */

struct fd_pstream
{
    struct pstream pstream;
    int fd;//fd
    //收到新的fd后执行此回调，创建新的stream
    int (*accept_cb)(int fd, const struct sockaddr_storage *, size_t ss_len,
                     struct stream **);
    char *unlink_path;//绑定的地址
};

static const struct pstream_class fd_pstream_class;

static struct fd_pstream *
fd_pstream_cast(struct pstream *pstream)
{
    pstream_assert_class(pstream, &fd_pstream_class);
    return CONTAINER_OF(pstream, struct fd_pstream, pstream);
}

/* Creates a new pstream named 'name' that will accept new socket connections
 * on 'fd' and stores a pointer to the stream in '*pstreamp'.
 *
 * When a connection has been accepted, 'accept_cb' will be called with the new
 * socket fd 'fd' and the remote address of the connection 'sa' and 'sa_len'.
 * accept_cb must return 0 if the connection is successful, in which case it
 * must initialize '*streamp' to the new stream, or a positive errno value on
 * error.  In either case accept_cb takes ownership of the 'fd' passed in.
 *
 * When '*pstreamp' is closed, then 'unlink_path' (if nonnull) will be passed
 * to fatal_signal_unlink_file_now() and freed with free().
 *
 * Takes ownership of 'name'.
 *
 * Returns 0 if successful, otherwise a positive errno value.  (The current
 * implementation never fails.) */
int
new_fd_pstream(char *name, int fd,
               int (*accept_cb)(int fd, const struct sockaddr_storage *ss,
                                size_t ss_len, struct stream **streamp),
               char *unlink_path, struct pstream **pstreamp)
{
    struct fd_pstream *ps = xmalloc(sizeof *ps);
    pstream_init(&ps->pstream, &fd_pstream_class, name);
    ps->fd = fd;
    ps->accept_cb = accept_cb;
    ps->unlink_path = unlink_path;
    *pstreamp = &ps->pstream;
    return 0;
}

static void
pfd_close(struct pstream *pstream)//pstream关闭函数
{
    struct fd_pstream *ps = fd_pstream_cast(pstream);
    closesocket(ps->fd);
    maybe_unlink_and_free(ps->unlink_path);
    free(ps);
}

//fd方式通用的accept
static int
pfd_accept(struct pstream *pstream, struct stream **new_streamp)//接受一个新的stream
{
    struct fd_pstream *ps = fd_pstream_cast(pstream);
    struct sockaddr_storage ss;
    socklen_t ss_len = sizeof ss;
    int new_fd;
    int retval;

    //If no pending connections are present on the queue, and the socket is not marked as nonblocking,
    //accept() blocks the caller until a connection is present.  If the socket is marked nonblocking
    //and no pending connections are present on the queue, accept() fails with the error EAGAIN or EWOULDBLOCK.
    new_fd = accept(ps->fd, (struct sockaddr *) &ss, &ss_len);//尝试着接受一个新的fd
    if (new_fd < 0) {//accept失败
        retval = sock_errno();
#ifdef _WIN32
        if (retval == WSAEWOULDBLOCK) {
            retval = EAGAIN;
        }
#endif
        if (retval != EAGAIN) {
            VLOG_DBG_RL(&rl, "accept: %s", sock_strerror(retval));
        }
        return retval;
    }

    retval = set_nonblocking(new_fd);//将新fd设置为非阻塞
    if (retval) {//如果设置非阻塞，则关闭fd
        closesocket(new_fd);
        return retval;
    }

    //然后调用上层的accept_cb(如unix_ctl注入的accept)
    return ps->accept_cb(new_fd, &ss, ss_len, new_streamp);
}

static void
pfd_wait(struct pstream *pstream)
{
    struct fd_pstream *ps = fd_pstream_cast(pstream);
    poll_fd_wait(ps->fd, POLLIN);
}

static const struct pstream_class fd_pstream_class = {
    "pstream",
    false,
    NULL,//由于打开时，已监听，故fd类型就不需要了
    pfd_close,
    pfd_accept,
    pfd_wait,
};

/* Helper functions. */
static void
maybe_unlink_and_free(char *path)
{
    if (path) {
        fatal_signal_unlink_file_now(path);
        free(path);
    }
}
