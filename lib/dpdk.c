/*
 * Copyright (c) 2014, 2015, 2016, 2017 Nicira, Inc.
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
#include "dpdk.h"

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <getopt.h>

#include <rte_log.h>
#include <rte_memzone.h>
#ifdef DPDK_PDUMP
#include <rte_mempool.h>
#include <rte_pdump.h>
#endif

#include "dirs.h"
#include "fatal-signal.h"
#include "netdev-dpdk.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/vlog.h"
#include "smap.h"

VLOG_DEFINE_THIS_MODULE(dpdk);

static FILE *log_stream = NULL;       /* Stream for DPDK log redirection */

static char *vhost_sock_dir = NULL;   /* Location of vhost-user sockets */

//检查ovs_other_config中是否有flag配置，如果有并且flag对应的配置字符串长度小于size，则使用配置的值
//否则使用default_val,在new_val中保持最终的值，返回0或者1来表示是否发生了变更。
static int
process_vhost_flags(char *flag, const char *default_val, int size,
                    const struct smap *ovs_other_config,
                    char **new_val)
{
    const char *val;
    int changed = 0;

    val = smap_get(ovs_other_config, flag);

    /* Process the vhost-sock-dir flag if it is provided, otherwise resort to
     * default value.
     */
    if (val && (strlen(val) <= size)) {
        changed = 1;
        *new_val = xstrdup(val);
        VLOG_INFO("User-provided %s in use: %s", flag, *new_val);
    } else {
        VLOG_INFO("No %s provided - defaulting to %s", flag, default_val);
        *new_val = xstrdup(default_val);
    }

    return changed;
}

static char **
grow_argv(char ***argv, size_t cur_siz, size_t grow_by)
{
    return xrealloc(*argv, sizeof(char *) * (cur_siz + grow_by));
}

static void
dpdk_option_extend(char ***argv, int argc, const char *option,
                   const char *value)
{
    char **newargv = grow_argv(argv, argc, 2);
    *argv = newargv;
    newargv[argc] = xstrdup(option);
    newargv[argc+1] = xstrdup(value);
}

static char **
move_argv(char ***argv, size_t cur_size, char **src_argv, size_t src_argc)
{
    char **newargv = grow_argv(argv, cur_size, src_argc);
    while (src_argc--) {
        newargv[cur_size+src_argc] = src_argv[src_argc];
        src_argv[src_argc] = NULL;
    }
    return newargv;
}

//从ovs_extra_config字符串中按空隔提取出token,并从argv[argc]这个位置开始存放
static int
extra_dpdk_args(const char *ovs_extra_config, char ***argv, int argc)
{
    int ret = argc;
    char *release_tok = xstrdup(ovs_extra_config);
    char *tok, *endptr = NULL;

    for (tok = strtok_r(release_tok, " ", &endptr); tok != NULL;
         tok = strtok_r(NULL, " ", &endptr)) {
        char **newarg = grow_argv(argv, ret, 1);
        *argv = newarg;
        newarg[ret++] = xstrdup(tok);
    }
    free(release_tok);
    return ret;
}

static bool
argv_contains(char **argv_haystack, const size_t argc_haystack,
              const char *needle)
{
    for (size_t i = 0; i < argc_haystack; ++i) {
        if (!strcmp(argv_haystack[i], needle))
            return true;
    }
    return false;
}

//处理opts中的选项
static int
construct_dpdk_options(const struct smap *ovs_other_config,
                       char ***argv, const int initial_size,
                       char **extra_args, const size_t extra_argc)
{
    struct dpdk_options_map {
        const char *ovs_configuration;
        const char *dpdk_option;
        bool default_enabled;
        const char *default_value;
    } opts[] = {
        {"dpdk-lcore-mask", "-c", false, NULL},
        {"dpdk-hugepage-dir", "--huge-dir", false, NULL},
    };

    int i, ret = initial_size;

    /*First, construct from the flat-options (non-mutex)*/
    for (i = 0; i < ARRAY_SIZE(opts); ++i) {
        const char *lookup = smap_get(ovs_other_config,
                                      opts[i].ovs_configuration);
        //如果没有提供此配置，但opt默认开启则使用默认值
        if (!lookup && opts[i].default_enabled) {
            lookup = opts[i].default_value;
        }

        if (lookup) {
        	//如果选项在extra_args中不存在，则加入
            if (!argv_contains(extra_args, extra_argc, opts[i].dpdk_option)) {
            	//lookup是其取值
                dpdk_option_extend(argv, ret, opts[i].dpdk_option, lookup);
                ret += 2;
            } else {
            	//如果extra_args中已存在，则忽略掉other_config中的配置
                VLOG_WARN("Ignoring database defined option '%s' due to "
                          "dpdk_extras config", opts[i].dpdk_option);
            }
        }
    }

    return ret;
}

#define MAX_DPDK_EXCL_OPTS 10

//检查excl_opts选项
static int
construct_dpdk_mutex_options(const struct smap *ovs_other_config,
                             char ***argv, const int initial_size,
                             char **extra_args, const size_t extra_argc)
{
    struct dpdk_exclusive_options_map {
        const char *category;
        const char *ovs_dpdk_options[MAX_DPDK_EXCL_OPTS];
        const char *eal_dpdk_options[MAX_DPDK_EXCL_OPTS];
        const char *default_value;
        int default_option;
    } excl_opts[] = {
        {"memory type",
         {"dpdk-alloc-mem", "dpdk-socket-mem", NULL,},
         {"-m",             "--socket-mem",    NULL,},
         "1024,0", 1
        },
    };

    int i, ret = initial_size;
    for (i = 0; i < ARRAY_SIZE(excl_opts); ++i) {
        int found_opts = 0, scan, found_pos = -1;
        const char *found_value;
        struct dpdk_exclusive_options_map *popt = &excl_opts[i];

        for (scan = 0; scan < MAX_DPDK_EXCL_OPTS
                 && popt->ovs_dpdk_options[scan]; ++scan) {
        	//检查ovs_other_config中是否配置了例如{'dpdk-all-mem','dpdk-socket-mem'}
            const char *lookup = smap_get(ovs_other_config,
                                          popt->ovs_dpdk_options[scan]);
            //如果出现多个，最后一个生效
            if (lookup && strlen(lookup)) {
                found_opts++;
                found_pos = scan;
                found_value = lookup;
            }
        }

        //找到了多个，取默认值
        if (!found_opts) {
            if (popt->default_option) {
                found_pos = popt->default_option;
                found_value = popt->default_value;
            } else {
                continue;
            }
        }

        //如果是多个，则报错
        if (found_opts > 1) {
            VLOG_ERR("Multiple defined options for %s. Please check your"
                     " database settings and reconfigure if necessary.",
                     popt->category);
        }

        //如果未指定，则加入argv
        if (!argv_contains(extra_args, extra_argc,
                           popt->eal_dpdk_options[found_pos])) {
            dpdk_option_extend(argv, ret, popt->eal_dpdk_options[found_pos],
                               found_value);
            ret += 2;
        } else {
        	//已指定，忽略数据库中的配置项
            VLOG_WARN("Ignoring database defined option '%s' due to "
                      "dpdk_extras config", popt->eal_dpdk_options[found_pos]);
        }
    }

    return ret;
}

static int
get_dpdk_args(const struct smap *ovs_other_config, char ***argv,
              int argc)
{
    const char *extra_configuration;
    char **extra_args = NULL;
    int i;
    size_t extra_argc = 0;

    //检查是否有'dpdk-extra'参数，例如dpdk-extra="-w 0000:81:00.1 -w 0000:06:00.0"
    extra_configuration = smap_get(ovs_other_config, "dpdk-extra");
    if (extra_configuration) {
    	//将extra_cfg按token存入到extra_args指针数组中
        extra_argc = extra_dpdk_args(extra_configuration, &extra_args, 0);
    }

    i = construct_dpdk_options(ovs_other_config, argv, argc, extra_args,
                               extra_argc);
    i = construct_dpdk_mutex_options(ovs_other_config, argv, i, extra_args,
                                     extra_argc);

    if (extra_configuration) {
    	//将extra_args合入argv中
        *argv = move_argv(argv, i, extra_args, extra_argc);
    }

    //返回参数总数
    return i + extra_argc;
}

static void
argv_release(char **dpdk_argv, char **dpdk_argv_release, size_t dpdk_argc)
{
    int result;
    for (result = 0; result < dpdk_argc; ++result) {
        free(dpdk_argv_release[result]);
    }

    free(dpdk_argv_release);
    free(dpdk_argv);
}

static ssize_t
dpdk_log_write(void *c OVS_UNUSED, const char *buf, size_t size)
{
    char *str = xmemdup0(buf, size);

    switch (rte_log_cur_msg_loglevel()) {
        case RTE_LOG_DEBUG:
            VLOG_DBG("%s", str);
            break;
        case RTE_LOG_INFO:
        case RTE_LOG_NOTICE:
            VLOG_INFO("%s", str);
            break;
        case RTE_LOG_WARNING:
            VLOG_WARN("%s", str);
            break;
        case RTE_LOG_ERR:
            VLOG_ERR("%s", str);
            break;
        case RTE_LOG_CRIT:
        case RTE_LOG_ALERT:
        case RTE_LOG_EMERG:
            VLOG_EMER("%s", str);
            break;
        default:
            OVS_NOT_REACHED();
    }

    free(str);
    return size;
}

static cookie_io_functions_t dpdk_log_func = {
    .write = dpdk_log_write,
};

//将other_config传入
static void
dpdk_init__(const struct smap *ovs_other_config)
{
    char **argv = NULL, **argv_to_release = NULL;
    int result;
    int argc, argc_tmp;
    bool auto_determine = true;
    int err = 0;
    cpu_set_t cpuset;
    char *sock_dir_subcomponent;

    log_stream = fopencookie(NULL, "w+", dpdk_log_func);
    if (log_stream == NULL) {
        VLOG_ERR("Can't redirect DPDK log: %s.", ovs_strerror(errno));
    } else {
        setbuf(log_stream, NULL);
        rte_openlog_stream(log_stream);
    }

    //检查vhost-sock-dir是否被指定了，且小于NAME_MAX
    if (process_vhost_flags("vhost-sock-dir", ovs_rundir(),
                            NAME_MAX, ovs_other_config,
                            &sock_dir_subcomponent)) {
    	//使用了用户指定的
        struct stat s;
        if (!strstr(sock_dir_subcomponent, "..")) {
        	//没有'..'符
            vhost_sock_dir = xasprintf("%s/%s", ovs_rundir(),
                                       sock_dir_subcomponent);

            //此目录必须存在
            err = stat(vhost_sock_dir, &s);
            if (err) {
                VLOG_ERR("vhost-user sock directory '%s' does not exist.",
                         vhost_sock_dir);
            }
        } else {
        	//含有'..'符，使用默认的
            vhost_sock_dir = xstrdup(ovs_rundir());
            VLOG_ERR("vhost-user sock directory request '%s/%s' has invalid"
                     "characters '..' - using %s instead.",
                     ovs_rundir(), sock_dir_subcomponent, ovs_rundir());
        }
        free(sock_dir_subcomponent);
    } else {
    	//使用的是非用户指定的
        vhost_sock_dir = sock_dir_subcomponent;
    }

    //当前版本中的argv实际上全部来源于ovs_other_config
    argv = grow_argv(&argv, 0, 1);
    argc = 1;
    argv[0] = xstrdup(ovs_get_program_name());//填充进程名

    //利用ovs_other_config中的参数构造argv,argc_tmp参数
    //在此函数里走一转，实际上没有意义。
    argc_tmp = get_dpdk_args(ovs_other_config, &argv, argc);

    while (argc_tmp != argc) {
    	//检查是否含有-c，-l参数
        if (!strcmp("-c", argv[argc]) || !strcmp("-l", argv[argc])) {
            auto_determine = false;
            break;
        }
        argc++;
    }
    argc = argc_tmp;

    /**
     * NOTE: This is an unsophisticated mechanism for determining the DPDK
     * lcore for the DPDK Master.
     */
    //未给出-c,-l参数，构造-c参数
    if (auto_determine) {
        int i;
        /* Get the main thread affinity */
        CPU_ZERO(&cpuset);
        err = pthread_getaffinity_np(pthread_self(), sizeof(cpu_set_t),
                                     &cpuset);
        if (!err) {
            for (i = 0; i < CPU_SETSIZE; i++) {
            	//取cpuset中的第一个cpu,并组装-c 参数
                if (CPU_ISSET(i, &cpuset)) {
                    argv = grow_argv(&argv, argc, 2);
                    argv[argc++] = xstrdup("-c");
                    argv[argc++] = xasprintf("0x%08llX", (1ULL<<i));
                    i = CPU_SETSIZE;
                }
            }
        } else {
        	//获取失败，则使用"-c 0x1"
            VLOG_ERR("Thread getaffinity error %d. Using core 0x1", err);
            /* User did not set dpdk-lcore-mask and unable to get current
             * thread affintity - default to core 0x1 */
            argv = grow_argv(&argv, argc, 2);
            argv[argc++] = xstrdup("-c");
            argv[argc++] = xasprintf("0x%X", 1);
        }
    }

    argv = grow_argv(&argv, argc, 1);
    argv[argc] = NULL;

    optind = 1;

    //如果此模块开启了info,则显示构造好的字符串
    if (VLOG_IS_INFO_ENABLED()) {
        struct ds eal_args;
        int opt;
        ds_init(&eal_args);
        ds_put_cstr(&eal_args, "EAL ARGS:");
        //将所有参数构造在字符中eal_args中
        for (opt = 0; opt < argc; ++opt) {
            ds_put_cstr(&eal_args, " ");
            ds_put_cstr(&eal_args, argv[opt]);
        }
        VLOG_INFO("%s", ds_cstr_ro(&eal_args));
        ds_destroy(&eal_args);
    }

    //构造argv_to_release，用于帮助释放，防止rte_eal_init把argv改了
    argv_to_release = grow_argv(&argv_to_release, 0, argc);
    for (argc_tmp = 0; argc_tmp < argc; ++argc_tmp) {
        argv_to_release[argc_tmp] = argv[argc_tmp];
    }

    /* Make sure things are initialized ... */
    //将参数构造并传入rte_eal_init
    result = rte_eal_init(argc, argv);
    if (result < 0) {
    	//初始化失败，主动退出
        ovs_abort(result, "Cannot init EAL");
    }
    //释放argv
    argv_release(argv, argv_to_release, argc);

    /* Set the main thread affinity back to pre rte_eal_init() value */
    if (auto_determine && !err) {
    	//设置到cpuset上
        err = pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t),
                                     &cpuset);
        if (err) {
            VLOG_ERR("Thread setaffinity error %d", err);
        }
    }

    //dump memzone
    rte_memzone_dump(stdout);

    /* We are called from the main thread here */
    //设置此线程的core_id
    RTE_PER_LCORE(_lcore_id) = NON_PMD_CORE_ID;

#ifdef DPDK_PDUMP
    VLOG_INFO("DPDK pdump packet capture enabled");
    err = rte_pdump_init(ovs_rundir());
    if (err) {
        VLOG_INFO("Error initialising DPDK pdump");
        rte_pdump_uninit();
    } else {
        char *server_socket_path;

        server_socket_path = xasprintf("%s/%s", ovs_rundir(),
                                       "pdump_server_socket");
        fatal_signal_add_file_to_unlink(server_socket_path);
        free(server_socket_path);
    }
#endif

    /* Finally, register the dpdk classes */
    //注册dpdk支持的驱动
    netdev_dpdk_register();
}

void
dpdk_init(const struct smap *ovs_other_config)
{
    static bool enabled = false;

    if (enabled || !ovs_other_config) {
        return;
    }

    //如果参数指定了dpdk-init
    if (smap_get_bool(ovs_other_config, "dpdk-init", false)) {
        static struct ovsthread_once once_enable = OVSTHREAD_ONCE_INITIALIZER;

        //ovs_other_config中的改动需要重启ovs
        if (ovsthread_once_start(&once_enable)) {
            VLOG_INFO("DPDK Enabled - initializing...");
            dpdk_init__(ovs_other_config);
            enabled = true;//只做一次
            VLOG_INFO("DPDK Enabled - initialized");
            ovsthread_once_done(&once_enable);
        }
    } else {
        VLOG_INFO_ONCE("DPDK Disabled - Use other_config:dpdk-init to enable");
    }
}

const char *
dpdk_get_vhost_sock_dir(void)
{
    return vhost_sock_dir;
}

void
dpdk_set_lcore_id(unsigned cpu)
{
    /* NON_PMD_CORE_ID is reserved for use by non pmd threads. */
    ovs_assert(cpu != NON_PMD_CORE_ID);
    RTE_PER_LCORE(_lcore_id) = cpu;
}
