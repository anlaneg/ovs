/* Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013, 2014, 2015, 2016 Nicira, Inc.
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

#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_MLOCKALL
#include <sys/mman.h>
#endif

#include "bridge.h"
#include "command-line.h"
#include "compiler.h"
#include "daemon.h"
#include "dirs.h"
#include "dpif.h"
#include "dummy.h"
#include "fatal-signal.h"
#include "memory.h"
#include "netdev.h"
#include "openflow/openflow.h"
#include "ovsdb-idl.h"
#include "ovs-rcu.h"
#include "ovs-router.h"
#include "ovs-thread.h"
#include "openvswitch/poll-loop.h"
#include "simap.h"
#include "stream-ssl.h"
#include "stream.h"
#include "svec.h"
#include "timeval.h"
#include "unixctl.h"
#include "util.h"
#include "openvswitch/vconn.h"
#include "openvswitch/vlog.h"
#include "lib/vswitch-idl.h"
#include "lib/dns-resolve.h"

VLOG_DEFINE_THIS_MODULE(vswitchd);

/* --mlockall: If set, locks all process memory into physical RAM, preventing
 * the kernel from paging any of its memory to disk. */
static bool want_mlockall;//防止内存被换出

static unixctl_cb_func ovs_vswitchd_exit;

static char *parse_options(int argc, char *argv[], char **unixctl_path);
OVS_NO_RETURN static void usage(void);

struct ovs_vswitchd_exit_args {
    bool *exiting;
    bool *cleanup;
};

int
main(int argc, char *argv[])
{
    char *unixctl_path = NULL;
    //unixctl服务器
    struct unixctl_server *unixctl;
    char *remote;
    bool exiting, cleanup;
    struct ovs_vswitchd_exit_args exit_args = {&exiting, &cleanup};
    int retval;

    //设置进程名称，进程版本号
    set_program_name(argv[0]);
    ovsthread_id_init();

    dns_resolve_init(true);
    //非linux机器不做作何处理
    ovs_cmdl_proctitle_init(argc, argv);
    //linux机器不做任何处理
    service_start(&argc, &argv);
    //解析命令行
    remote = parse_options(argc, argv, &unixctl_path);
    //忽略pipe信号
    fatal_ignore_sigpipe();

    //完成daemon创建
    daemonize_start(true);

    if (want_mlockall) {//锁内存处理
#ifdef HAVE_MLOCKALL
        if (mlockall(MCL_CURRENT | MCL_FUTURE)) {
            VLOG_ERR("mlockall failed: %s", ovs_strerror(errno));
        } else {
            set_memory_locked();
        }
#else
        VLOG_ERR("mlockall not supported on this system");
#endif
    }

    //创建unix控制端服务器
    retval = unixctl_server_create(unixctl_path, &unixctl);
    if (retval) {
        exit(EXIT_FAILURE);
    }
    unixctl_command_register("exit", "[--cleanup]", 0, 1,
                             ovs_vswitchd_exit, &exit_args);//注册退出命令

    //命令及ovsdb连接初始化
    bridge_init(remote);
    free(remote);

    exiting = false;
    cleanup = false;

    while (!exiting) {
        memory_run();
        if (memory_should_report()) {
            struct simap usage;

            simap_init(&usage);
            bridge_get_memory_usage(&usage);
            memory_report(&usage);
            simap_destroy(&usage);
        }

        bridge_run();
        unixctl_server_run(unixctl);
        //由此函数下去，经dpif_netdev_run->reconfigure_datapath->...可到达pmd_thread_main
        netdev_run();

        //wait代码段
        memory_wait();
        bridge_wait();
        unixctl_server_wait(unixctl);
        netdev_wait();
        if (exiting) {
        	//立即触发poll_block()
            poll_immediate_wake();
        }
        //阻塞等待事件
        poll_block();
        if (should_service_stop()) {
            exiting = true;
        }
    }
    bridge_exit(cleanup);
    unixctl_server_destroy(unixctl);
    service_stop();
    vlog_disable_async();
    ovsrcu_exit();
    dns_resolve_destroy();

    return 0;
}

static char *
parse_options(int argc, char *argv[], char **unixctl_pathp)
//解析命令行，设置相关全局配置，返回database路径
{
    enum {
        OPT_PEER_CA_CERT = UCHAR_MAX + 1,
        OPT_MLOCKALL,
        OPT_UNIXCTL,
        VLOG_OPTION_ENUMS,
        OPT_BOOTSTRAP_CA_CERT,
        OPT_ENABLE_DUMMY,
        OPT_DISABLE_SYSTEM,
        OPT_DISABLE_SYSTEM_ROUTE,
        DAEMON_OPTION_ENUMS,
        OPT_DPDK,
        SSL_OPTION_ENUMS,
        OPT_DUMMY_NUMA,
    };
    static const struct option long_options[] = {
        {"help",        no_argument, NULL, 'h'},
        {"version",     no_argument, NULL, 'V'},
        {"mlockall",    no_argument, NULL, OPT_MLOCKALL},
        {"unixctl",     required_argument, NULL, OPT_UNIXCTL},
        DAEMON_LONG_OPTIONS,
        VLOG_LONG_OPTIONS,
        STREAM_SSL_LONG_OPTIONS,
        {"peer-ca-cert", required_argument, NULL, OPT_PEER_CA_CERT},
        {"bootstrap-ca-cert", required_argument, NULL, OPT_BOOTSTRAP_CA_CERT},
        {"enable-dummy", optional_argument, NULL, OPT_ENABLE_DUMMY},//是否需要开启dummy
        {"disable-system", no_argument, NULL, OPT_DISABLE_SYSTEM},//禁止system类型的datapath
        {"disable-system-route", no_argument, NULL, OPT_DISABLE_SYSTEM_ROUTE},
        {"dpdk", optional_argument, NULL, OPT_DPDK},
        {"dummy-numa", required_argument, NULL, OPT_DUMMY_NUMA},
        {NULL, 0, NULL, 0},
    };
    char *short_options = ovs_cmdl_long_options_to_short_options(long_options);

    for (;;) {
        int c;

        c = getopt_long(argc, argv, short_options, long_options, NULL);
        if (c == -1) {//最后一个
            break;
        }

        switch (c) {
        case 'h':
            usage();

        case 'V':
            ovs_print_version(0, 0);
            print_dpdk_version();
            exit(EXIT_SUCCESS);

        case OPT_MLOCKALL:
            want_mlockall = true;
            break;

        case OPT_UNIXCTL:
            *unixctl_pathp = optarg;//overwrite unixctl路径
            break;

        VLOG_OPTION_HANDLERS //log选项处理
        DAEMON_OPTION_HANDLERS //demon相关处理
        STREAM_SSL_OPTION_HANDLERS //ssl选项处理

        case OPT_PEER_CA_CERT:
            stream_ssl_set_peer_ca_cert_file(optarg);
            break;

        case OPT_BOOTSTRAP_CA_CERT:
            stream_ssl_set_ca_cert_file(optarg, true);
            break;

        case OPT_ENABLE_DUMMY:
            dummy_enable(optarg);//dummy处理,从实现来看，仅用于测试
            break;

        case OPT_DISABLE_SYSTEM:
            //禁用system类型
            dp_disallow_provider("system");
            break;

        case OPT_DISABLE_SYSTEM_ROUTE:
            ovs_router_disable_system_routing_table();
            break;

        case '?':
            exit(EXIT_FAILURE);

        case OPT_DPDK://不再支持直接配置dpdk
            ovs_fatal(0, "Using --dpdk to configure DPDK is not supported.");
            break;

        case OPT_DUMMY_NUMA:
            ovs_numa_set_dummy(optarg);
            break;

        default:
            abort();
        }
    }
    free(short_options);

    argc -= optind;
    argv += optind;

    switch (argc) {//检查是否给出database
    case 0://没有给出
        return xasprintf("unix:%s/db.sock", ovs_rundir());

    case 1://给出了
        return xstrdup(argv[0]);

    default:
        VLOG_FATAL("at most one non-option argument accepted; "
                   "use --help for usage");
    }
}

static void
usage(void)//用法信息
{
    printf("%s: Open vSwitch daemon\n"
           "usage: %s [OPTIONS] [DATABASE]\n"
           "where DATABASE is a socket on which ovsdb-server is listening\n"
           "      (default: \"unix:%s/db.sock\").\n",
           program_name, program_name, ovs_rundir());//显示总述 ovswitch [option] [database]
    stream_usage("DATABASE", true, false, true);//database主动方式
    daemon_usage();//demon相关的提示
    vlog_usage();//log相关的用法
    printf("\nDPDK options:\n"
           "Configuration of DPDK via command-line is removed from this\n"
           "version of Open vSwitch. DPDK is configured through ovsdb.\n"
          );//dpdk配置提示（通过ovs进行非透明配置）
    printf("\nOther options:\n"
           "  --unixctl=SOCKET          override default control socket name\n"
           "  -h, --help                display this help message\n"
           "  -V, --version             display version information\n");
    exit(EXIT_SUCCESS);
}

static void
ovs_vswitchd_exit(struct unixctl_conn *conn, int argc,
                  const char *argv[], void *exit_args_)//vswitchd退出处理
{
    struct ovs_vswitchd_exit_args *exit_args = exit_args_;
    *exit_args->exiting = true;
    *exit_args->cleanup = argc == 2 && !strcmp(argv[1], "--cleanup");
    unixctl_command_reply(conn, NULL);
}
