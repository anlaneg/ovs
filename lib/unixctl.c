/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013, 2014, 2016 Nicira, Inc.
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
#include "unixctl.h"
#include <errno.h>
#include <unistd.h>
#include "coverage.h"
#include "dirs.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/json.h"
#include "jsonrpc.h"
#include "openvswitch/list.h"
#include "openvswitch/poll-loop.h"
#include "openvswitch/shash.h"
#include "stream.h"
#include "stream-provider.h"
#include "svec.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(unixctl);

COVERAGE_DEFINE(unixctl_received);
COVERAGE_DEFINE(unixctl_replied);

struct unixctl_command {
    const char *usage;//命令的提示信息
    int min_args, max_args;//命令的最大最小参数
    unixctl_cb_func *cb;//命令的回调
    void *aux;//用户自定义参数
};

struct unixctl_conn {
    struct ovs_list node;
    struct jsonrpc *rpc;

    /* Only one request can be in progress at a time.  While the request is
     * being processed, 'request_id' is populated, otherwise it is null. */
    struct json *request_id;   /* ID of the currently active request. */
};

/* Server for control connection. */
struct unixctl_server {
    struct pstream *listener;//监听unixctl-server
    struct ovs_list conns;//接入的所有远程连接（struct unixctl_conn）
    char *path;
};

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 5);

//保存所有的command(unixctl命令）
static struct shash commands = SHASH_INITIALIZER(&commands);

//列出所有命令
static void
unixctl_list_commands(struct unixctl_conn *conn, int argc OVS_UNUSED,
                      const char *argv[] OVS_UNUSED, void *aux OVS_UNUSED)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    const struct shash_node **nodes = shash_sort(&commands);
    size_t i;

    ds_put_cstr(&ds, "The available commands are:\n");

    for (i = 0; i < shash_count(&commands); i++) {
        const struct shash_node *node = nodes[i];
        const struct unixctl_command *command = node->data;

        //填充名称 名称，提示信息到ds
        if (command->usage) {
            ds_put_format(&ds, "  %-23s %s\n", node->name, command->usage);
        }
    }
    free(nodes);

    //将ds内的数据返回给用户
    unixctl_command_reply(conn, ds_cstr(&ds));
    ds_destroy(&ds);//释放空间
}

//取版本号
static void
unixctl_version(struct unixctl_conn *conn, int argc OVS_UNUSED,
                const char *argv[] OVS_UNUSED, void *aux OVS_UNUSED)
{
    unixctl_command_reply(conn, ovs_get_program_version());//取版本号
}

/* Registers a unixctl command with the given 'name'.  'usage' describes the
 * arguments to the command; it is used only for presentation to the user in
 * "list-commands" output.  (If 'usage' is NULL, then the command is hidden.)
 *
 * 'cb' is called when the command is received.  It is passed an array
 * containing the command name and arguments, plus a copy of 'aux'.  Normally
 * 'cb' should reply by calling unixctl_command_reply() or
 * unixctl_command_reply_error() before it returns, but if the command cannot
 * be handled immediately then it can defer the reply until later.  A given
 * connection can only process a single request at a time, so a reply must be
 * made eventually to avoid blocking that connection. */
//实现命令注册
void
unixctl_command_register(const char *name/*命令名*/, const char *usage/*用法说明*/,
                         int min_args/*最小参数数*/, int max_args/*最大参数数*/,
                         unixctl_cb_func *cb/*命令处理回调*/, void *aux)
{
    struct unixctl_command *command;
    struct unixctl_command *lookup = shash_find_data(&commands, name);

    ovs_assert(!lookup || lookup->cb == cb);

    if (lookup) {
    	//如果已存在，则不容许变更，直接返回
        return;
    }

    command = xmalloc(sizeof *command);
    command->usage = usage;
    command->min_args = min_args;
    command->max_args = max_args;
    command->cb = cb;
    command->aux = aux;
    //将command加入总hash表
    shash_add(&commands, name, command);
}

//命令响应底层
static void
unixctl_command_reply__(struct unixctl_conn *conn,
                        bool success, const char *body)
{
    struct json *body_json;
    struct jsonrpc_msg *reply;

    COVERAGE_INC(unixctl_replied);
    ovs_assert(conn->request_id);

    if (!body) {//无内容，响应空串
        body = "";
    }

    if (body[0] && body[strlen(body) - 1] != '\n') {//有值，没有以'\n'结尾
        body_json = json_string_create_nocopy(xasprintf("%s\n", body));
    } else {
        body_json = json_string_create(body);
    }

    if (success) {
        reply = jsonrpc_create_reply(body_json, conn->request_id);
    } else {
        reply = jsonrpc_create_error(body_json, conn->request_id);
    }

    if (VLOG_IS_DBG_ENABLED()) {
        char *id = json_to_string(conn->request_id, 0);
        VLOG_DBG("replying with %s, id=%s: \"%s\"",
                 success ? "success" : "error", id, body);
        free(id);
    }

    /* If jsonrpc_send() returns an error, the run loop will take care of the
     * problem eventually. */
    jsonrpc_send(conn->rpc, reply);
    json_destroy(conn->request_id);//清空json请求
    conn->request_id = NULL;
}

/* Replies to the active unixctl connection 'conn'.  'result' is sent to the
 * client indicating the command was processed successfully.  Only one call to
 * unixctl_command_reply() or unixctl_command_reply_error() may be made per
 * request. */
//成功时响应结果
void
unixctl_command_reply(struct unixctl_conn *conn, const char *result)
{
    unixctl_command_reply__(conn, true, result);//成功执行时响应
}

/* Replies to the active unixctl connection 'conn'. 'error' is sent to the
 * client indicating an error occurred processing the command.  Only one call to
 * unixctl_command_reply() or unixctl_command_reply_error() may be made per
 * request. */
//错误响应
void
unixctl_command_reply_error(struct unixctl_conn *conn, const char *error)
{
    unixctl_command_reply__(conn, false, error);//失败执行时响应
}

/* Creates a unixctl server listening on 'path', which for POSIX may be:
 *
 *      - NULL, in which case <rundir>/<program>.<pid>.ctl is used.
 *
 *      - A name that does not start with '/', in which case it is put in
 *        <rundir>.
 *
 *      - An absolute path (starting with '/') that gives the exact name of
 *        the Unix domain socket to listen on.
 *
 * For Windows, a local named pipe is used. A file is created in 'path'
 * which may be:
 *
 *      - NULL, in which case <rundir>/<program>.ctl is used.
 *
 *      - An absolute path that gives the name of the file.
 *
 * For both POSIX and Windows, if the path is "none", the function will
 * return successfully but no socket will actually be created.
 *
 * A program that (optionally) daemonizes itself should call this function
 * *after* daemonization, so that the socket name contains the pid of the
 * daemon instead of the pid of the program that exited.  (Otherwise,
 * "ovs-appctl --target=<program>" will fail.)
 *
 * Returns 0 if successful, otherwise a positive errno value.  If successful,
 * sets '*serverp' to the new unixctl_server (or to NULL if 'path' was "none"),
 * otherwise to NULL. */
//创建unixctl-server
int
unixctl_server_create(const char *path, struct unixctl_server **serverp)
{
    *serverp = NULL;
    if (path && !strcmp(path, "none")) {
        return 0;
    }

#ifdef _WIN32
    enum { WINDOWS = 1 };
#else
    enum { WINDOWS = 0 };
#endif

    long int pid = getpid();
    //未指定path,自已构造path
    char *abs_path
        = (path ? abs_file_name(ovs_rundir(), path)
           : WINDOWS ? xasprintf("%s/%s.ctl", ovs_rundir(), program_name)
           : xasprintf("%s/%s.%ld.ctl", ovs_rundir(), program_name, pid));

    struct pstream *listener;
    char *punix_path = xasprintf("punix:%s", abs_path);//添加路径协议头
    int error = pstream_open(punix_path, &listener, 0);//创建对应的pstream
    free(punix_path);

    if (error) {
        ovs_error(error, "%s: could not initialize control socket", abs_path);
        free(abs_path);
        return error;
    }

    //注册列出所有command
    unixctl_command_register("list-commands", "", 0, 0, unixctl_list_commands,
                             NULL);
    //注册显示版本
    unixctl_command_register("version", "", 0, 0, unixctl_version, NULL);

    //创建unix-server
    struct unixctl_server *server = xmalloc(sizeof *server);
    server->listener = listener;
    server->path = abs_path;
    ovs_list_init(&server->conns);//初始化与客户端的连接

    *serverp = server;
    return 0;
}

//处理unixctl命令
static void
process_command(struct unixctl_conn *conn, struct jsonrpc_msg *request)
{
    char *error = NULL;

    struct unixctl_command *command;
    struct json_array *params;

    COVERAGE_INC(unixctl_received);
    conn->request_id = json_clone(request->id);

    //log显示
    if (VLOG_IS_DBG_ENABLED()) {
        char *params_s = json_to_string(request->params, 0);
        char *id_s = json_to_string(request->id, 0);
        VLOG_DBG("received request %s%s, id=%s",
                 request->method, params_s, id_s);
        free(params_s);
        free(id_s);
    }

    params = json_array(request->params);
    //找出要调用的命令，并进行简单的参数检查
    command = shash_find_data(&commands, request->method);
    if (!command) {
        //无此对应的命令
        error = xasprintf("\"%s\" is not a valid command (use "
                          "\"list-commands\" to see a list of valid commands)",
                          request->method);
    } else if (params->n < command->min_args) {
    	//参数过少
        error = xasprintf("\"%s\" command requires at least %d arguments",
                          request->method, command->min_args);
    } else if (params->n > command->max_args) {
    	//参数过多
        error = xasprintf("\"%s\" command takes at most %d arguments",
                          request->method, command->max_args);
    } else {
        struct svec argv = SVEC_EMPTY_INITIALIZER;
        int  i;

        //将method加入
        svec_add(&argv, request->method);
        //将参数加入
        for (i = 0; i < params->n; i++) {
            if (params->elems[i]->type != JSON_STRING) {
                error = xasprintf("\"%s\" command has non-string argument",
                                  request->method);
                break;
            }
            svec_add(&argv, json_string(params->elems[i]));
        }
        //通过NULL来标记数组最后一元素s
        svec_terminate(&argv);

        if (!error) {
        	//回调命令（参数总数，参数数组，用户自定义参数
            command->cb(conn, argv.n, (const char **) argv.names,
                        command->aux);
        }

        svec_destroy(&argv);//销毁argv
    }

    //如果都没有调回调，就发生错误，则直接返回错误
    if (error) {
    	//有错误，则返回错误，否则由命令回复客户端
        unixctl_command_reply_error(conn, error);
        free(error);
    }
}

//自对应连接上收取数据，并解析jsonrpc形成命令，执行命令
static int
run_connection(struct unixctl_conn *conn)//自此连接收取并处理消息
{
    int error, i;

    jsonrpc_run(conn->rpc);
    error = jsonrpc_get_status(conn->rpc);
    if (error || jsonrpc_get_backlog(conn->rpc)) {
        //处理时出错或者状态有误
        return error;
    }

    for (i = 0; i < 10; i++) {
        //尝试收取10次
        struct jsonrpc_msg *msg;

        if (error || conn->request_id) {
            break;
        }

        jsonrpc_recv(conn->rpc, &msg);
        if (msg) {
        	//收取到一个消息
            if (msg->type == JSONRPC_REQUEST) {
            	//rpc请求消息
                process_command(conn, msg);//处理命令行
            } else {
                VLOG_WARN_RL(&rl, "%s: received unexpected %s message",
                             jsonrpc_get_name(conn->rpc),
                             jsonrpc_msg_type_to_string(msg->type));
                error = EINVAL;
            }
            jsonrpc_msg_destroy(msg);
        }
        error = error ? error : jsonrpc_get_status(conn->rpc);
    }

    return error;
}

//丢弃连接
static void
kill_connection(struct unixctl_conn *conn)
{
    ovs_list_remove(&conn->node);
    jsonrpc_close(conn->rpc);
    json_destroy(conn->request_id);
    free(conn);
}

//server层面的维护，封装server下的所有connection的收发
void
unixctl_server_run(struct unixctl_server *server)//unixctl-server处理
{
    if (!server) {
        return;
    }

    for (int i = 0; i < 10; i++) {
        //尝试着接入几个unixctl客户端
        struct stream *stream;
        int error;

        //由于socket被设置为非阻塞，故这里accept不会阻塞
        error = pstream_accept(server->listener, &stream);
        if (!error) {
            struct unixctl_conn *conn = xzalloc(sizeof *conn);
            //将新接入的conn加入到server的connection管理中
            ovs_list_push_back(&server->conns, &conn->node);
            conn->rpc = jsonrpc_open(stream);
        } else if (error == EAGAIN) {
            break;
        } else {
            VLOG_WARN_RL(&rl, "%s: accept failed: %s",
                         pstream_get_name(server->listener),
                         ovs_strerror(error));
        }
    }

    struct unixctl_conn *conn;
    //遍历server管理的connect
    LIST_FOR_EACH_SAFE (conn, node, &server->conns) {
        //处理unixctl消息
        int error = run_connection(conn);
        if (error && error != EAGAIN) {
            //发生错误，中断连接
            kill_connection(conn);
        }
    }
}

//产生wait句柄，准备poll
void
unixctl_server_wait(struct unixctl_server *server)
{
    struct unixctl_conn *conn;

    if (!server) {
        return;
    }

    pstream_wait(server->listener);
    LIST_FOR_EACH (conn, node, &server->conns) {
        jsonrpc_wait(conn->rpc);
        if (!jsonrpc_get_backlog(conn->rpc) && !conn->request_id) {
            jsonrpc_recv_wait(conn->rpc);
        }
    }
}

/* Destroys 'server' and stops listening for connections. */
//server销毁
void
unixctl_server_destroy(struct unixctl_server *server)
{
    if (server) {
        struct unixctl_conn *conn;

        LIST_FOR_EACH_SAFE (conn, node, &server->conns) {
            kill_connection(conn);
        }

        free(server->path);
        pstream_close(server->listener);
        free(server);
    }
}

const char *
unixctl_server_get_path(const struct unixctl_server *server)
{
    return server ? server->path : NULL;
}

/* On POSIX based systems, connects to a unixctl server socket.  'path' should
 * be the name of a unixctl server socket.  If it does not start with '/', it
 * will be prefixed with the rundir (e.g. /usr/local/var/run/openvswitch).
 *
 * On Windows, connects to a local named pipe. A file which resides in
 * 'path' is used to mimic the behavior of a Unix domain socket.
 * 'path' should be an absolute path of the file.
 *
 * Returns 0 if successful, otherwise a positive errno value.  If successful,
 * sets '*client' to the new jsonrpc, otherwise to NULL. */
//客户端创建
int
unixctl_client_create(const char *path, struct jsonrpc **client)
{
    struct stream *stream;
    int error;

    char *abs_path = abs_file_name(ovs_rundir(), path);
    char *unix_path = xasprintf("unix:%s", abs_path);

    *client = NULL;

    error = stream_open_block(stream_open(unix_path, &stream, DSCP_DEFAULT),
                              -1, &stream);
    free(unix_path);
    free(abs_path);

    if (error) {
        VLOG_WARN("failed to connect to %s", path);
        return error;
    }

    *client = jsonrpc_open(stream);
    return 0;
}

/* Executes 'command' on the server with an argument vector 'argv' containing
 * 'argc' elements.  If successfully communicated with the server, returns 0
 * and sets '*result', or '*err' (not both) to the result or error the server
 * returned.  Otherwise, sets '*result' and '*err' to NULL and returns a
 * positive errno value.  The caller is responsible for freeing '*result' or
 * '*err' if not NULL. */
//向unixctl-server发送请求（细节是：将command封装成jsonrpc,并解析server的响应)
int
unixctl_client_transact(struct jsonrpc *client, const char *command, int argc,
                        char *argv[], char **result, char **err)
{
    struct jsonrpc_msg *request, *reply;
    struct json **json_args, *params;
    int error, i;

    *result = NULL;
    *err = NULL;

    json_args = xmalloc(argc * sizeof *json_args);
    for (i = 0; i < argc; i++) {
        json_args[i] = json_string_create(argv[i]);
    }

    //json字符串数组
    params = json_array_create(json_args, argc);
    request = jsonrpc_create_request(command, params, NULL);

    error = jsonrpc_transact_block(client, request, &reply);
    if (error) {
        VLOG_WARN("error communicating with %s: %s", jsonrpc_get_name(client),
                  ovs_retval_to_string(error));
        return error;
    }

    if (reply->error) {
        if (reply->error->type == JSON_STRING) {
            *err = xstrdup(json_string(reply->error));
        } else {
            VLOG_WARN("%s: unexpected error type in JSON RPC reply: %s",
                      jsonrpc_get_name(client),
                      json_type_to_string(reply->error->type));
            error = EINVAL;
        }
    } else if (reply->result) {
        if (reply->result->type == JSON_STRING) {
            *result = xstrdup(json_string(reply->result));
        } else {
            VLOG_WARN("%s: unexpected result type in JSON rpc reply: %s",
                      jsonrpc_get_name(client),
                      json_type_to_string(reply->result->type));
            error = EINVAL;
        }
    }

    jsonrpc_msg_destroy(reply);
    return error;
}
