/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013, 2014 Nicira, Inc.
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
#include "openvswitch/poll-loop.h"
#include <errno.h>
#include <inttypes.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include "coverage.h"
#include "openvswitch/dynamic-string.h"
#include "fatal-signal.h"
#include "openvswitch/list.h"
#include "ovs-thread.h"
#include "seq.h"
#include "socket-util.h"
#include "timeval.h"
#include "openvswitch/vlog.h"
#include "openvswitch/hmap.h"
#include "hash.h"

VLOG_DEFINE_THIS_MODULE(poll_loop);

COVERAGE_DEFINE(poll_create_node);
COVERAGE_DEFINE(poll_zero_timeout);

struct poll_node {
    struct hmap_node hmap_node;
    struct pollfd pollfd;       /* Events to pass to time_poll(). */ //poll参数
    HANDLE wevent;              /* Events for WaitForMultipleObjects(). *///windows事件，同linux fd
    const char *where;          /* Where poll_node was created. *///位置
};

struct poll_loop {
    /* All active poll waiters. */
    struct hmap poll_nodes;//持有所有poll_node

    /* Time at which to wake up the next call to poll_block(), LLONG_MIN to
     * wake up immediately, or LLONG_MAX to wait forever. */
    long long int timeout_when; /* In msecs as returned by time_msec(). */ //超时时间
    const char *timeout_where;  /* Where 'timeout_when' was set. */ //当时等待的位置
};

static struct poll_loop *poll_loop(void);

/* Look up the node with same fd or wevent. */
//通过fd,wevent在loop上查找poll_node
static struct poll_node *
find_poll_node(struct poll_loop *loop, int fd, HANDLE wevent)
{
    struct poll_node *node;

    /* Both 'fd' and 'wevent' cannot be set. */
    ovs_assert(!fd != !wevent);

    HMAP_FOR_EACH_WITH_HASH (node, hmap_node,
                             hash_2words(fd, (uint32_t)wevent),
                             &loop->poll_nodes) {
        if ((fd && node->pollfd.fd == fd)//fd相同
            || (wevent && node->wevent == wevent)) {//windows事件相同
            return node;
        }
    }
    return NULL;
}

/* On Unix based systems:
 *
 *     Registers 'fd' as waiting for the specified 'events' (which should be
 *     POLLIN or POLLOUT or POLLIN | POLLOUT).  The following call to
 *     poll_block() will wake up when 'fd' becomes ready for one or more of the
 *     requested events. The 'fd's are given to poll() function later.
 *
 * On Windows system:
 *
 *     If 'fd' is specified, create a new 'wevent'. Association of 'fd' and
 *     'wevent' for 'events' happens in poll_block(). If 'wevent' is specified,
 *     it is assumed that it is unrelated to any sockets and poll_block()
 *     will wake up on any event on that 'wevent'. It is an error to pass
 *     both 'wevent' and 'fd'.
 *
 * The event registration is one-shot: only the following call to
 * poll_block() is affected.  The event will need to be re-registered after
 * poll_block() is called if it is to persist.
 *
 * ('where' is used in debug logging.  Commonly one would use poll_fd_wait() to
 * automatically provide the caller's source file and line number for
 * 'where'.) */
static void
poll_create_node(int fd, HANDLE wevent, short int events, const char *where)//创建必要的poll_node
{
    /*取当前线程的poll loop*/
    struct poll_loop *loop = poll_loop();
    struct poll_node *node;

    COVERAGE_INC(poll_create_node);

    /* Both 'fd' and 'wevent' cannot be set. */
    ovs_assert(!fd != !wevent);

    /* Check for duplicate.  If found, "or" the events. */
    node = find_poll_node(loop, fd, wevent);
    if (node) {
        //此fd已注册，添加关注的事件
        node->pollfd.events |= events;
    } else {
        //此fd不存在，则加入新节点,添加关注的事件
        node = xzalloc(sizeof *node);
        hmap_insert(&loop->poll_nodes, &node->hmap_node,
                    hash_2words(fd, (uint32_t)wevent));
        node->pollfd.fd = fd;
        node->pollfd.events = events;
#ifdef _WIN32
        if (!wevent) {
            wevent = CreateEvent(NULL, FALSE, FALSE, NULL);
        }
#endif
        node->wevent = wevent;
        node->where = where;
    }
}

/* Registers 'fd' as waiting for the specified 'events' (which should be POLLIN
 * or POLLOUT or POLLIN | POLLOUT).  The following call to poll_block() will
 * wake up when 'fd' becomes ready for one or more of the requested events.
 *
 * On Windows, 'fd' must be a socket.
 *
 * The event registration is one-shot: only the following call to poll_block()
 * is affected.  The event will need to be re-registered after poll_block() is
 * called if it is to persist.
 *
 * ('where' is used in debug logging.  Commonly one would use poll_fd_wait() to
 * automatically provide the caller's source file and line number for
 * 'where'.) */
//创建fd等待
void
poll_fd_wait_at(int fd, short int events, const char *where)
{
    //创建poll node(为linux wevent事件为0)
    poll_create_node(fd, 0, events, where);
}

#ifdef _WIN32
/* Registers for the next call to poll_block() to wake up when 'wevent' is
 * signaled.
 *
 * The event registration is one-shot: only the following call to poll_block()
 * is affected.  The event will need to be re-registered after poll_block() is
 * called if it is to persist.
 *
 * ('where' is used in debug logging.  Commonly one would use
 * poll_wevent_wait() to automatically provide the caller's source file and
 * line number for 'where'.) */
void
poll_wevent_wait_at(HANDLE wevent, const char *where)
{
    poll_create_node(0, wevent, 0, where);
}
#endif /* _WIN32 */

/* Causes the following call to poll_block() to block for no more than 'msec'
 * milliseconds.  If 'msec' is nonpositive, the following call to poll_block()
 * will not block at all.
 *
 * The timer registration is one-shot: only the following call to poll_block()
 * is affected.  The timer will need to be re-registered after poll_block() is
 * called if it is to persist.
 *
 * ('where' is used in debug logging.  Commonly one would use poll_timer_wait()
 * to automatically provide the caller's source file and line number for
 * 'where'.) */
//注册需要本线程等待的最小时间（可以采纳，也可能不采纳{不采纳时有更小的等待时间}）
void
poll_timer_wait_at(long long int msec, const char *where)
{
    long long int now = time_msec();
    long long int when;

    if (msec <= 0) {
        /* Wake up immediately. */
        when = LLONG_MIN;//设置为最小时间
    } else if ((unsigned long long int) now + msec <= LLONG_MAX) {
        /* Normal case. */
        when = now + msec;//普通情况，设置触发时间
    } else {
        /* now + msec would overflow. */
        when = LLONG_MAX;//设置为最大时间
    }

    poll_timer_wait_until_at(when, where);
}

/* Causes the following call to poll_block() to wake up when the current time,
 * as returned by time_msec(), reaches 'when' or later.  If 'when' is earlier
 * than the current time, the following call to poll_block() will not block at
 * all.
 *
 * The timer registration is one-shot: only the following call to poll_block()
 * is affected.  The timer will need to be re-registered after poll_block() is
 * called if it is to persist.
 *
 * ('where' is used in debug logging.  Commonly one would use
 * poll_timer_wait_until() to automatically provide the caller's source file
 * and line number for 'where'.) */
//尝试更新需要等待的最小时间
void
poll_timer_wait_until_at(long long int when, const char *where)
{
    struct poll_loop *loop = poll_loop();
    if (when < loop->timeout_when) {
    	//设置loop时间及位置，设置所有等待中最小的时间
        loop->timeout_when = when;
        loop->timeout_where = where;
    }
}

/* Causes the following call to poll_block() to wake up immediately, without
 * blocking.
 *
 * ('where' is used in debug logging.  Commonly one would use
 * poll_immediate_wake() to automatically provide the caller's source file and
 * line number for 'where'.) */
void
poll_immediate_wake_at(const char *where)
{
    //注册为0间隔的timer,暗示poll_block可以立即返回
    poll_timer_wait_at(0, where);
}

/* Logs, if appropriate, that the poll loop was awakened by an event
 * registered at 'where' (typically a source file and line number).  The other
 * arguments have two possible interpretations:
 *
 *   - If 'pollfd' is nonnull then it should be the "struct pollfd" that caused
 *     the wakeup.  'timeout' is ignored.
 *
 *   - If 'pollfd' is NULL then 'timeout' is the number of milliseconds after
 *     which the poll loop woke up.
 */
static void
log_wakeup(const char *where, const struct pollfd *pollfd, int timeout)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(10, 10);
    enum vlog_level level;
    int cpu_usage;
    struct ds s;

    cpu_usage = get_cpu_usage();
    if (VLOG_IS_DBG_ENABLED()) {
        level = VLL_DBG;
    } else if (cpu_usage > 50
               && !thread_is_pmd()
               && !VLOG_DROP_INFO(&rl)) {
        level = VLL_INFO;
    } else {
        return;
    }

    ds_init(&s);
    ds_put_cstr(&s, "wakeup due to ");
    if (pollfd) {
        char *description = describe_fd(pollfd->fd);
        if (pollfd->revents & POLLIN) {
            ds_put_cstr(&s, "[POLLIN]");
        }
        if (pollfd->revents & POLLOUT) {
            ds_put_cstr(&s, "[POLLOUT]");
        }
        if (pollfd->revents & POLLERR) {
            ds_put_cstr(&s, "[POLLERR]");
        }
        if (pollfd->revents & POLLHUP) {
            ds_put_cstr(&s, "[POLLHUP]");
        }
        if (pollfd->revents & POLLNVAL) {
            ds_put_cstr(&s, "[POLLNVAL]");
        }
        ds_put_format(&s, " on fd %d (%s)", pollfd->fd, description);
        free(description);
    } else {
        ds_put_format(&s, "%d-ms timeout", timeout);
    }
    if (where) {
        ds_put_format(&s, " at %s", where);
    }
    if (cpu_usage >= 0) {
        ds_put_format(&s, " (%d%% CPU usage)", cpu_usage);
    }
    VLOG(level, "%s", ds_cstr(&s));
    ds_destroy(&s);
}

static void
free_poll_nodes(struct poll_loop *loop)
{
    struct poll_node *node;

    HMAP_FOR_EACH_SAFE (node, hmap_node, &loop->poll_nodes) {
        hmap_remove(&loop->poll_nodes, &node->hmap_node);
#ifdef _WIN32
        if (node->wevent && node->pollfd.fd) {
            WSAEventSelect(node->pollfd.fd, NULL, 0);
            CloseHandle(node->wevent);
        }
#endif
        free(node);
    }
}

/* Blocks until one or more of the events registered with poll_fd_wait()
 * occurs, or until the minimum duration registered with poll_timer_wait()
 * elapses, or not at all if poll_immediate_wake() has been called. */
//等待事件触发（会被递归调用）参阅以上注释
void
poll_block(void)
{
	//取当前线程poll_loop
    struct poll_loop *loop = poll_loop();
    struct poll_node *node;
    struct pollfd *pollfds;
    HANDLE *wevents = NULL;
    int elapsed;
    int retval;
    int i;

    /* Register fatal signal events before actually doing any real work for
     * poll_block. */
    //注册信号事件，使poll_block可处理信号
    fatal_signal_wait();

    if (loop->timeout_when == LLONG_MIN) {
    	//非常短的超时时间，增加zero timeout统计
        COVERAGE_INC(poll_zero_timeout);
    }

    timewarp_run();

    //申请足够数量的poolfd
    pollfds = xmalloc(hmap_count(&loop->poll_nodes) * sizeof *pollfds);

#ifdef _WIN32
    wevents = xmalloc(hmap_count(&loop->poll_nodes) * sizeof *wevents);
#endif

    /* Populate with all the fds and events. */
    //遍历挂接在loop上的所有node，收集其上注册的fd到pollfds数组
    i = 0;
    HMAP_FOR_EACH (node, hmap_node, &loop->poll_nodes) {
    	//填充这些pollfd到pollfds数组
        pollfds[i] = node->pollfd;
#ifdef _WIN32
        wevents[i] = node->wevent;
        if (node->pollfd.fd && node->wevent) {
            short int wsa_events = 0;
            if (node->pollfd.events & POLLIN) {
                wsa_events |= FD_READ | FD_ACCEPT | FD_CLOSE;
            }
            if (node->pollfd.events & POLLOUT) {
                wsa_events |= FD_WRITE | FD_CONNECT | FD_CLOSE;
            }
            WSAEventSelect(node->pollfd.fd, node->wevent, wsa_events);
        }
#endif
        i++;
    }

    retval = time_poll(pollfds, hmap_count(&loop->poll_nodes), wevents,
                       loop->timeout_when, &elapsed);
    if (retval < 0) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_ERR_RL(&rl, "poll: %s", ovs_strerror(-retval));
    } else if (!retval) {
        log_wakeup(loop->timeout_where, NULL, elapsed);
    } else if (get_cpu_usage() > 50 || VLOG_IS_DBG_ENABLED()) {
        /*cpu利用率大于50%*/
        i = 0;
        HMAP_FOR_EACH (node, hmap_node, &loop->poll_nodes) {
            if (pollfds[i].revents) {
                log_wakeup(node->where, &pollfds[i], 0);
            }
            i++;
        }
    }

    free_poll_nodes(loop);
    loop->timeout_when = LLONG_MAX;//设置等待事件为最大，接受下一轮定义
    loop->timeout_where = NULL;
    free(pollfds);
    free(wevents);

    /* Handle any pending signals before doing anything else. */
    fatal_signal_run();

    seq_woke();
}

static void
free_poll_loop(void *loop_)
{
    struct poll_loop *loop = loop_;

    free_poll_nodes(loop);
    hmap_destroy(&loop->poll_nodes);
    free(loop);
}

//返回当前线程对应的poll_loop
static struct poll_loop *
poll_loop(void)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;
    static pthread_key_t key;
    struct poll_loop *loop;

    if (ovsthread_once_start(&once)) {
        //创建key并设置key对应的释放函数
        xpthread_key_create(&key, free_poll_loop);
        ovsthread_once_done(&once);
    }

    loop = pthread_getspecific(key);
    if (!loop) {
        //如果key对应的loop没有创建，则创建它，并指定超时时间为无限
        loop = xzalloc(sizeof *loop);
        loop->timeout_when = LLONG_MAX;
        hmap_init(&loop->poll_nodes);
        xpthread_setspecific(key, loop);
    }
    return loop;
}

