/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013, 2015, 2016 Nicira, Inc.
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
#include "openvswitch/vlog.h"
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>
#include "async-append.h"
#include "coverage.h"
#include "dirs.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/ofpbuf.h"
#include "ovs-thread.h"
#include "sat-math.h"
#include "socket-util.h"
#include "svec.h"
#include "syslog-direct.h"
#include "syslog-libc.h"
#include "syslog-null.h"
#include "syslog-provider.h"
#include "timeval.h"
#include "unixctl.h"
#include "util.h"

VLOG_DEFINE_THIS_MODULE(vlog);

/* ovs_assert() logs the assertion message, so using ovs_assert() in this
 * source file could cause recursion. */
#undef ovs_assert
#define ovs_assert use_assert_instead_of_ovs_assert_in_this_module

/* Name for each logging level. */
static const char *const level_names[VLL_N_LEVELS] = {
#define VLOG_LEVEL(NAME, SYSLOG_LEVEL, RFC5424) #NAME,
    VLOG_LEVELS
#undef VLOG_LEVEL
};

/* Syslog value for each logging level. */
static const int syslog_levels[VLL_N_LEVELS] = {
#define VLOG_LEVEL(NAME, SYSLOG_LEVEL, RFC5424) SYSLOG_LEVEL,
    VLOG_LEVELS
#undef VLOG_LEVEL
};

/* RFC 5424 defines specific values for each syslog level.  Normally LOG_* use
 * the same values.  Verify that in fact they're the same.  If we get assertion
 * failures here then we need to define a separate rfc5424_levels[] array. */
#define VLOG_LEVEL(NAME, SYSLOG_LEVEL, RFC5424) \
    BUILD_ASSERT_DECL(SYSLOG_LEVEL == RFC5424);
VLOG_LEVELS
#undef VLOG_LEVELS

/* Similarly, RFC 5424 defines the local0 facility with the value ordinarily
 * used for LOG_LOCAL0. */
BUILD_ASSERT_DECL(LOG_LOCAL0 == (16 << 3));

/* Protects the 'pattern' in all "struct destination"s, so that a race between
 * changing and reading the pattern does not cause an access to freed
 * memory. */
static struct ovs_rwlock pattern_rwlock = OVS_RWLOCK_INITIALIZER;

/* Information about each destination. */
struct destination {
    const char *name;           /* Name. */
    char *pattern OVS_GUARDED_BY(pattern_rwlock); /* Current pattern. */
    bool default_pattern;       /* Whether current pattern is the default. */
};

//指明输出目的的名称，模式
static struct destination destinations[VLF_N_DESTINATIONS] = {
#define VLOG_DESTINATION(NAME, PATTERN) {#NAME, PATTERN, true},
    VLOG_DESTINATIONS
#undef VLOG_DESTINATION
};

/* Sequence number for the message currently being composed. */
DEFINE_STATIC_PER_THREAD_DATA(unsigned int, msg_num, 0);

/* VLF_FILE configuration.
 *
 * All of the following is protected by 'log_file_mutex', which nests inside
 * pattern_rwlock. */
static struct ovs_mutex log_file_mutex OVS_ACQ_AFTER(pattern_rwlock)
    = OVS_MUTEX_INITIALIZER;
//日志文件对应的文件名称
static char *log_file_name OVS_GUARDED_BY(log_file_mutex) = NULL;
//日志文件对应的fd
static int log_fd OVS_GUARDED_BY(log_file_mutex) = -1;
static struct async_append *log_writer OVS_GUARDED_BY(log_file_mutex);
static bool log_async OVS_GUARDED_BY(log_file_mutex);
static struct syslogger *syslogger = NULL;

/* The log modules. */
//记录所有需要log的模块
static struct ovs_list vlog_modules OVS_GUARDED_BY(log_file_mutex)
    = OVS_LIST_INITIALIZER(&vlog_modules);

/* Syslog export configuration. */
static int syslog_fd OVS_GUARDED_BY(pattern_rwlock) = -1;

/* Log facility configuration. */
static atomic_int log_facility = ATOMIC_VAR_INIT(0);

/* Facility name and its value. */
struct vlog_facility {
    char *name;           /* Name. */
    unsigned int value;   /* Facility associated with 'name'. */
};
static struct vlog_facility vlog_facilities[] = {
    {"kern", LOG_KERN},
    {"user", LOG_USER},
    {"mail", LOG_MAIL},
    {"daemon", LOG_DAEMON},
    {"auth", LOG_AUTH},
    {"syslog", LOG_SYSLOG},
    {"lpr", LOG_LPR},
    {"news", LOG_NEWS},
    {"uucp", LOG_UUCP},
    {"clock", LOG_CRON},
    {"ftp", LOG_FTP},
    {"ntp", 12<<3},
    {"audit", 13<<3},
    {"alert", 14<<3},
    {"clock2", 15<<3},
    {"local0", LOG_LOCAL0},
    {"local1", LOG_LOCAL1},
    {"local2", LOG_LOCAL2},
    {"local3", LOG_LOCAL3},
    {"local4", LOG_LOCAL4},
    {"local5", LOG_LOCAL5},
    {"local6", LOG_LOCAL6},
    {"local7", LOG_LOCAL7}
};
static bool vlog_facility_exists(const char* facility, int *value);

static void format_log_message(const struct vlog_module *, enum vlog_level,
                               const char *pattern,
                               const char *message, va_list, struct ds *)
    OVS_PRINTF_FORMAT(4, 0);

/* Searches the 'n_names' in 'names'.  Returns the index of a match for
 * 'target', or 'n_names' if no name matches. */
static size_t
search_name_array(const char *target, const char *const *names, size_t n_names)
{
    size_t i;

    for (i = 0; i < n_names; i++) {
        assert(names[i]);
        if (!strcasecmp(names[i], target)) {
            break;
        }
    }
    return i;
}

/* Returns the name for logging level 'level'. */
const char *
vlog_get_level_name(enum vlog_level level)
{
    assert(level < VLL_N_LEVELS);
    return level_names[level];
}

/* Returns the logging level with the given 'name', or VLL_N_LEVELS if 'name'
 * is not the name of a logging level. */
enum vlog_level
vlog_get_level_val(const char *name)
{
    return search_name_array(name, level_names, ARRAY_SIZE(level_names));
}

/* Returns the name for logging destination 'destination'. */
const char *
vlog_get_destination_name(enum vlog_destination destination)
{
    assert(destination < VLF_N_DESTINATIONS);
    return destinations[destination].name;
}

/* Returns the logging destination named 'name', or VLF_N_DESTINATIONS if
 * 'name' is not the name of a logging destination. */
//通过名称获知输出方式
enum vlog_destination
vlog_get_destination_val(const char *name)
{
    size_t i;

    for (i = 0; i < VLF_N_DESTINATIONS; i++) {
        if (!strcasecmp(destinations[i].name, name)) {
            break;
        }
    }
    return i;
}

//将log模块加入到系统log_modules表中
void
vlog_insert_module(struct ovs_list *vlog)
{
    ovs_mutex_lock(&log_file_mutex);
    ovs_list_insert(&vlog_modules, vlog);
    ovs_mutex_unlock(&log_file_mutex);
}

/* Returns the name for logging module 'module'. */
const char *
vlog_get_module_name(const struct vlog_module *module)
{
    return module->name;
}

/* Returns the logging module named 'name', or NULL if 'name' is not the name
 * of a logging module. */
//通过名称返回模块
struct vlog_module *
vlog_module_from_name(const char *name)
{
    struct vlog_module *mp;

    ovs_mutex_lock(&log_file_mutex);
    LIST_FOR_EACH (mp, list, &vlog_modules) {
        if (!strcasecmp(name, mp->name)) {
            ovs_mutex_unlock(&log_file_mutex);
            return mp;
        }
    }
    ovs_mutex_unlock(&log_file_mutex);

    return NULL;
}

/* Returns the current logging level for the given 'module' and
 * 'destination'. */
enum vlog_level
vlog_get_level(const struct vlog_module *module,
               enum vlog_destination destination)
{
    assert(destination < VLF_N_DESTINATIONS);
    return module->levels[destination];
}

static void
update_min_level(struct vlog_module *module) OVS_REQUIRES(log_file_mutex)
{
    enum vlog_destination destination;

    module->min_level = VLL_OFF;
    for (destination = 0; destination < VLF_N_DESTINATIONS; destination++) {
        if (log_fd >= 0 || destination != VLF_FILE) {
            enum vlog_level level = module->levels[destination];
            if (level > module->min_level) {
                module->min_level = level;
            }
        }
    }
}

static void
set_destination_level(enum vlog_destination destination,
                      struct vlog_module *module, enum vlog_level level)
{
    assert(destination >= 0 && destination < VLF_N_DESTINATIONS);
    assert(level < VLL_N_LEVELS);

    ovs_mutex_lock(&log_file_mutex);
	//未指定模块，则为所有模块
    if (!module) {
        struct vlog_module *mp;
        //遍历所有模块日志对象,并设置其level
        LIST_FOR_EACH (mp, list, &vlog_modules) {
            mp->levels[destination] = level;
            update_min_level(mp);//更新此模块的最小level
        }
    } else {
        module->levels[destination] = level;
        update_min_level(module);
    }
    ovs_mutex_unlock(&log_file_mutex);
}

/* Sets the logging level for the given 'module' and 'destination' to 'level'.
 * A null 'module' or a 'destination' of VLF_ANY_DESTINATION is treated as a
 * wildcard across all modules or destinations, respectively. */
void
vlog_set_levels(struct vlog_module *module, enum vlog_destination destination,
                enum vlog_level level)
{
    assert(destination < VLF_N_DESTINATIONS ||
           destination == VLF_ANY_DESTINATION);
    //如果是设置所有输出目的地，则循环设置
    if (destination == VLF_ANY_DESTINATION) {
        for (destination = 0; destination < VLF_N_DESTINATIONS;
             destination++) {
            set_destination_level(destination, module, level);
        }
    } else {
    	//设置单个目的地
        set_destination_level(destination, module, level);
    }
}

static void
do_set_pattern(enum vlog_destination destination, const char *pattern)
{
    struct destination *f = &destinations[destination];

    ovs_rwlock_wrlock(&pattern_rwlock);
    if (!f->default_pattern) {
        free(f->pattern);
    } else {
        f->default_pattern = false;
    }
    f->pattern = xstrdup(pattern);
    ovs_rwlock_unlock(&pattern_rwlock);
}

/* Sets the pattern for the given 'destination' to 'pattern'. */
void
vlog_set_pattern(enum vlog_destination destination, const char *pattern)
{
    assert(destination < VLF_N_DESTINATIONS ||
           destination == VLF_ANY_DESTINATION);
    if (destination == VLF_ANY_DESTINATION) {
        for (destination = 0; destination < VLF_N_DESTINATIONS;
             destination++) {
            do_set_pattern(destination, pattern);
        }
    } else {
        do_set_pattern(destination, pattern);
    }
}

/* Returns a copy of the name of the log file used by VLF_FILE, or NULL if none
 * is configured.  The caller must eventually free the returned string. */
char *
vlog_get_log_file(void)
{
    ovs_mutex_lock(&log_file_mutex);
    char *fn = nullable_xstrdup(log_file_name);
    ovs_mutex_unlock(&log_file_mutex);

    return fn;
}

/* Sets the name of the log file used by VLF_FILE to 'new_log_file_name', or
 * closes the current log file if 'new_log_file_name' is NULL.  Takes ownership
 * of 'new_log_file_name'.  Returns 0 if successful, otherwise a positive errno
 * value. */
static int
vlog_set_log_file__(char *new_log_file_name)
{
    struct vlog_module *mp;
    struct stat old_stat;
    struct stat new_stat;
    int new_log_fd;
    bool same_file;
    bool log_close;

    /* Open new log file. */
    if (new_log_file_name) {
        new_log_fd = open(new_log_file_name, O_WRONLY | O_CREAT | O_APPEND,
                          0660);
        if (new_log_fd < 0) {
            VLOG_WARN("failed to open %s for logging: %s",
                      new_log_file_name, ovs_strerror(errno));
            free(new_log_file_name);
            return errno;
        }
    } else {
        new_log_fd = -1;
    }

    /* If the new log file is the same one we already have open, bail out. */
    ovs_mutex_lock(&log_file_mutex);
    same_file = ((log_fd < 0
                  && new_log_fd < 0) ||
                 (log_fd >= 0
                  && new_log_fd >= 0
                  && !fstat(log_fd, &old_stat)
                  && !fstat(new_log_fd, &new_stat)
                  && old_stat.st_dev == new_stat.st_dev
                  && old_stat.st_ino == new_stat.st_ino));
    ovs_mutex_unlock(&log_file_mutex);
    if (same_file) {
        close(new_log_fd);
        free(new_log_file_name);
        return 0;
    }

    /* Log closing old log file (we can't log while holding log_file_mutex). */
    ovs_mutex_lock(&log_file_mutex);
    log_close = log_fd >= 0;
    ovs_mutex_unlock(&log_file_mutex);
    if (log_close) {
        VLOG_INFO("closing log file");
    }

    /* Close old log file, if any. */
    ovs_mutex_lock(&log_file_mutex);
    if (log_fd >= 0) {
        close(log_fd);
    }
    async_append_destroy(log_writer);
    free(log_file_name);

    /* Install new log file. */
    log_file_name = nullable_xstrdup(new_log_file_name);
    log_fd = new_log_fd;
    log_writer = log_async ? async_append_create(new_log_fd) : NULL;

    LIST_FOR_EACH (mp, list, &vlog_modules) {
        update_min_level(mp);
    }
    ovs_mutex_unlock(&log_file_mutex);

    /* Log opening new log file (we can't log while holding log_file_mutex). */
    VLOG_INFO("opened log file %s", new_log_file_name);
    free(new_log_file_name);

    return 0;
}

/* Closes the log file, if any.
 *
 * If the real goal is open a new log file, use vlog_set_log_file() to directly
 * do that: there is no need to close the old file first. */
void
vlog_close_log_file(void)
{
    vlog_set_log_file__(NULL);
}

/* Sets the name of the log file used by VLF_FILE to 'file_name', or to the
 * default file name if 'file_name' is null.  Returns 0 if successful,
 * otherwise a positive errno value. */
int
vlog_set_log_file(const char *file_name)
{
    return vlog_set_log_file__(
        file_name
        ? xstrdup(file_name)
        : xasprintf("%s/%s.log", ovs_logdir(), program_name));
}

/* Closes and then attempts to re-open the current log file.  (This is useful
 * just after log rotation, to ensure that the new log file starts being used.)
 * Returns 0 if successful, otherwise a positive errno value. */
int
vlog_reopen_log_file(void)
{
    char *fn;

    ovs_mutex_lock(&log_file_mutex);
    fn = nullable_xstrdup(log_file_name);
    ovs_mutex_unlock(&log_file_mutex);

    if (fn) {
        int error = vlog_set_log_file(fn);
        free(fn);
        return error;
    } else {
        return 0;
    }
}

#ifndef _WIN32
/* In case a log file exists, change its owner to new 'user' and 'group'.
 *
 * This is useful for handling cases where the --log-file option is
 * specified ahead of the --user option.  */
void
vlog_change_owner_unix(uid_t user, gid_t group)
{
    struct ds err = DS_EMPTY_INITIALIZER;
    int error;

    ovs_mutex_lock(&log_file_mutex);
    //更改log_file的owner
    error = log_file_name ? chown(log_file_name, user, group) : 0;
    if (error) {
        /* Build the error message. We can not call VLOG_FATAL directly
         * here because VLOG_FATAL() will try again to to acquire
         * 'log_file_mutex' lock, causing deadlock.
         */
        ds_put_format(&err, "Failed to change %s ownership: %s.",
                      log_file_name, ovs_strerror(errno));
    }
    ovs_mutex_unlock(&log_file_mutex);

    if (error) {
        VLOG_FATAL("%s", ds_steal_cstr(&err));
    }
}
#endif

/* Set debugging levels.  Returns null if successful, otherwise an error
 * message that the caller must free(). */
char *
vlog_set_levels_from_string(const char *s_)
{
    char *s = xstrdup(s_);
    char *save_ptr = NULL;
    char *msg = NULL;
    char *word;

    word = strtok_r(s, " ,:\t", &save_ptr);
    if (word && !strcasecmp(word, "PATTERN")) {
        enum vlog_destination destination;

        word = strtok_r(NULL, " ,:\t", &save_ptr);
        if (!word) {
            msg = xstrdup("missing destination");
            goto exit;
        }

        destination = (!strcasecmp(word, "ANY")
                       ? VLF_ANY_DESTINATION
                       : vlog_get_destination_val(word));
        if (destination == VLF_N_DESTINATIONS) {
            msg = xasprintf("unknown destination \"%s\"", word);
            goto exit;
        }
        vlog_set_pattern(destination, save_ptr);
    } else if (word && !strcasecmp(word, "FACILITY")) {
        int value;

        if (!vlog_facility_exists(save_ptr, &value)) {
            msg = xstrdup("invalid facility");
            goto exit;
        }
        atomic_store_explicit(&log_facility, value, memory_order_relaxed);
    } else {
        struct vlog_module *module = NULL;
        enum vlog_level level = VLL_N_LEVELS;
        enum vlog_destination destination = VLF_N_DESTINATIONS;

        for (; word != NULL; word = strtok_r(NULL, " ,:\t", &save_ptr)) {
            if (!strcasecmp(word, "ANY")) {
            	//如果遇到ANY,则跳过
                continue;
            } else if (vlog_get_destination_val(word) != VLF_N_DESTINATIONS) {
            	//将word尝试着解析为destination,解析成功后，检查是否已指定，如果指定，则报错
                if (destination != VLF_N_DESTINATIONS) {
                    msg = xstrdup("cannot specify multiple destinations");
                    goto exit;
                }

                destination = vlog_get_destination_val(word);
            } else if (vlog_get_level_val(word) != VLL_N_LEVELS) {
            	//将word尝试解析为level,如果解析成功后，检查是否已指定，如果已指定，则报错
                if (level != VLL_N_LEVELS) {
                    msg = xstrdup("cannot specify multiple levels");
                    goto exit;
                }
                level = vlog_get_level_val(word);
            } else if (vlog_module_from_name(word)) {
            	//将word尝试解析为module,如果解析成功，则检查是否已指定，如果已指定，则报错
                if (module) {
                    msg = xstrdup("cannot specify multiple modules");
                    goto exit;
                }
                module = vlog_module_from_name(word);
            } else {
            	//处理不被成功识别的word
                msg = xasprintf("no destination, level, or module \"%s\"",
                                word);
                goto exit;
            }
        }

        //如果未指定destination,则使用ANY
        if (destination == VLF_N_DESTINATIONS) {
            destination = VLF_ANY_DESTINATION;
        }
        //如果未指定level，则使用dbg
        if (level == VLL_N_LEVELS) {
            level = VLL_DBG;
        }

        //设置对应的module,如果module为NULL,则所有
        vlog_set_levels(module, destination, level);
    }

exit:
    free(s);
    return msg;
}

/* Set debugging levels.  Abort with an error message if 's' is invalid. */
void
vlog_set_levels_from_string_assert(const char *s)
{
    char *error = vlog_set_levels_from_string(s);
    if (error) {
        ovs_fatal(0, "%s", error);
    }
}

/* If 'arg' is null, configure maximum verbosity.  Otherwise, sets
 * configuration according to 'arg' (see vlog_set_levels_from_string()). */
void
vlog_set_verbosity(const char *arg)
{
    if (arg) {
        char *msg = vlog_set_levels_from_string(arg);
        if (msg) {
            ovs_fatal(0, "processing \"%s\": %s", arg, msg);
        }
    } else {
        vlog_set_levels(NULL, VLF_ANY_DESTINATION, VLL_DBG);
    }
}

void
vlog_set_syslog_method(const char *method)
{
    if (syslogger) {
        /* Set syslogger only, if one is not already set.  This effectively
         * means that only the first --syslog-method argument is honored. */
        return;
    }

    if (!strcmp(method, "null")) {
        syslogger = syslog_null_create();
    } else if (!strcmp(method, "libc")) {
        syslogger = syslog_libc_create();
    } else if (!strncmp(method, "udp:", 4) || !strncmp(method, "unix:", 5)) {
        syslogger = syslog_direct_create(method);
    } else {
        ovs_fatal(0, "unsupported syslog method '%s'", method);
    }
}

/* Set the vlog udp syslog target. */
void
vlog_set_syslog_target(const char *target)
{
    int new_fd;

    inet_open_active(SOCK_DGRAM, target, -1, NULL, &new_fd, 0);

    ovs_rwlock_wrlock(&pattern_rwlock);
    if (syslog_fd >= 0) {
        close(syslog_fd);
    }
    syslog_fd = new_fd;
    ovs_rwlock_unlock(&pattern_rwlock);
}

/*
 * This function writes directly to log file without using async writer or
 * taking a lock.  Caller must hold 'log_file_mutex' or be sure that it's
 * not necessary.  Could be used in exceptional cases like dumping of backtrace
 * on fatal signals.
 */
void
vlog_direct_write_to_log_file_unsafe(const char *s)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    if (log_fd >= 0) {
        ignore(write(log_fd, s, strlen(s)));
    }
}

/* Returns 'false' if 'facility' is not a valid string. If 'facility'
 * is a valid string, sets 'value' with the integer value of 'facility'
 * and returns 'true'. */
static bool
vlog_facility_exists(const char* facility, int *value)
{
    size_t i;
    for (i = 0; i < ARRAY_SIZE(vlog_facilities); i++) {
        if (!strcasecmp(vlog_facilities[i].name, facility)) {
            *value = vlog_facilities[i].value;
            return true;
        }
    }
    return false;
}

static void
vlog_unixctl_set(struct unixctl_conn *conn, int argc, const char *argv[],
                 void *aux OVS_UNUSED)
{
    int i;

    /* With no argument, set all destinations and modules to "dbg". */
    if (argc == 1) {
        vlog_set_levels(NULL, VLF_ANY_DESTINATION, VLL_DBG);
    }
    for (i = 1; i < argc; i++) {
        char *msg = vlog_set_levels_from_string(argv[i]);
        if (msg) {
            unixctl_command_reply_error(conn, msg);
            free(msg);
            return;
        }
    }
    unixctl_command_reply(conn, NULL);
}

static void
vlog_unixctl_list(struct unixctl_conn *conn, int argc OVS_UNUSED,
                  const char *argv[] OVS_UNUSED, void *aux OVS_UNUSED)
{
    char *msg = vlog_get_levels();
    unixctl_command_reply(conn, msg);
    free(msg);
}

static void
vlog_unixctl_list_pattern(struct unixctl_conn *conn, int argc OVS_UNUSED,
                          const char *argv[] OVS_UNUSED, void *aux OVS_UNUSED)
{
    char *msg;

    msg = vlog_get_patterns();
    unixctl_command_reply(conn, msg);
    free(msg);
}

static void
vlog_unixctl_reopen(struct unixctl_conn *conn, int argc OVS_UNUSED,
                    const char *argv[] OVS_UNUSED, void *aux OVS_UNUSED)
{
    bool has_log_file;

    ovs_mutex_lock(&log_file_mutex);
    has_log_file = log_file_name != NULL;
    ovs_mutex_unlock(&log_file_mutex);

    if (has_log_file) {
        int error = vlog_reopen_log_file();
        if (error) {
            unixctl_command_reply_error(conn, ovs_strerror(errno));
        } else {
            unixctl_command_reply(conn, NULL);
        }
    } else {
        unixctl_command_reply_error(conn, "Logging to file not configured");
    }
}

static void
vlog_unixctl_close(struct unixctl_conn *conn, int argc OVS_UNUSED,
                   const char *argv[] OVS_UNUSED, void *aux OVS_UNUSED)
{
    ovs_mutex_lock(&log_file_mutex);
    if (log_fd >= 0) {
        close(log_fd);
        log_fd = -1;

        async_append_destroy(log_writer);
        log_writer = NULL;

        struct vlog_module *mp;
        LIST_FOR_EACH (mp, list, &vlog_modules) {
            update_min_level(mp);
        }
    }
    ovs_mutex_unlock(&log_file_mutex);

    unixctl_command_reply(conn, NULL);
}

static void
set_all_rate_limits(bool enable)
{
    struct vlog_module *mp;

    ovs_mutex_lock(&log_file_mutex);
    LIST_FOR_EACH (mp, list, &vlog_modules) {
        mp->honor_rate_limits = enable;
    }
    ovs_mutex_unlock(&log_file_mutex);
}

static void
set_rate_limits(struct unixctl_conn *conn, int argc,
                const char *argv[], bool enable)
{
    if (argc > 1) {
        int i;

        for (i = 1; i < argc; i++) {
            if (!strcasecmp(argv[i], "ANY")) {
                set_all_rate_limits(enable);
            } else {
                struct vlog_module *module = vlog_module_from_name(argv[i]);
                if (!module) {
                    unixctl_command_reply_error(conn, "unknown module");
                    return;
                }
                module->honor_rate_limits = enable;
            }
        }
    } else {
        set_all_rate_limits(enable);
    }
    unixctl_command_reply(conn, NULL);
}

static void
vlog_enable_rate_limit(struct unixctl_conn *conn, int argc,
                       const char *argv[], void *aux OVS_UNUSED)
{
    set_rate_limits(conn, argc, argv, true);
}

static void
vlog_disable_rate_limit(struct unixctl_conn *conn, int argc,
                       const char *argv[], void *aux OVS_UNUSED)
{
    set_rate_limits(conn, argc, argv, false);
}

/* Initializes the logging subsystem and registers its unixctl server
 * commands. */
void
vlog_init(void)
{
    //vlog子系统初始化
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;

    if (ovsthread_once_start(&once)) {
        long long int now;
        int facility;
        bool print_syslog_target_deprecation;

        /* Do initialization work that needs to be done before any logging
         * occurs.  We want to keep this really minimal because any attempt to
         * log anything before calling ovsthread_once_done() will deadlock. */
        atomic_read_explicit(&log_facility, &facility, memory_order_relaxed);
        if (!syslogger) {
            char *env = getenv("OVS_SYSLOG_METHOD");
            if (env && env[0]) {
                vlog_set_syslog_method(env);
            } else {
                syslogger = syslog_libc_create();
            }
        }
        syslogger->class->openlog(syslogger, facility ? facility : LOG_DAEMON);
        ovsthread_once_done(&once);

        /* Now do anything that we want to happen only once but doesn't have to
         * finish before we start logging. */

        now = time_wall_msec();
        if (now < 0) {
            char *s = xastrftime_msec("%a, %d %b %Y %H:%M:%S", now, true);
            VLOG_ERR("current time is negative: %s (%lld)", s, now);
            free(s);
        }

        unixctl_command_register(
            "vlog/set", "{spec | PATTERN:destination:pattern}",
            0, INT_MAX, vlog_unixctl_set, NULL);
        unixctl_command_register("vlog/list", "", 0, 0, vlog_unixctl_list,
                                 NULL);
        unixctl_command_register("vlog/list-pattern", "", 0, 0,
                                 vlog_unixctl_list_pattern, NULL);
        unixctl_command_register("vlog/enable-rate-limit", "[module]...",
                                 0, INT_MAX, vlog_enable_rate_limit, NULL);
        unixctl_command_register("vlog/disable-rate-limit", "[module]...",
                                 0, INT_MAX, vlog_disable_rate_limit, NULL);
        unixctl_command_register("vlog/reopen", "", 0, 0,
                                 vlog_unixctl_reopen, NULL);
        unixctl_command_register("vlog/close", "", 0, 0,
                                 vlog_unixctl_close, NULL);

        ovs_rwlock_rdlock(&pattern_rwlock);
        print_syslog_target_deprecation = syslog_fd >= 0;
        ovs_rwlock_unlock(&pattern_rwlock);

        if (print_syslog_target_deprecation) {
            VLOG_WARN("--syslog-target flag is deprecated, use "
                      "--syslog-method instead");
        }
    }
}

/* Enables VLF_FILE log output to be written asynchronously to disk.
 * Asynchronous file writes avoid blocking the process in the case of a busy
 * disk, but on the other hand they are less robust: there is a chance that the
 * write will not make it to the log file if the process crashes soon after the
 * log call. */
void
vlog_enable_async(void)
{
    ovs_mutex_lock(&log_file_mutex);
    log_async = true;
    if (log_fd >= 0 && !log_writer) {
        log_writer = async_append_create(log_fd);
    }
    ovs_mutex_unlock(&log_file_mutex);
}

void
vlog_disable_async(void)
{
    ovs_mutex_lock(&log_file_mutex);
    log_async = false;
    async_append_destroy(log_writer);
    log_writer = NULL;
    ovs_mutex_unlock(&log_file_mutex);
}

/* Print the current logging level for each module. */
char *
vlog_get_levels(void)
{
    struct ds s = DS_EMPTY_INITIALIZER;
    struct vlog_module *mp;
    struct svec lines = SVEC_EMPTY_INITIALIZER;
    size_t i;

    ds_put_format(&s, "                 console    syslog    file\n");
    ds_put_format(&s, "                 -------    ------    ------\n");

    ovs_mutex_lock(&log_file_mutex);
    LIST_FOR_EACH (mp, list, &vlog_modules) {
        struct ds line;

        ds_init(&line);
        ds_put_format(&line, "%-16s  %4s       %4s       %4s",
                      vlog_get_module_name(mp),
                      vlog_get_level_name(vlog_get_level(mp, VLF_CONSOLE)),
                      vlog_get_level_name(vlog_get_level(mp, VLF_SYSLOG)),
                      vlog_get_level_name(vlog_get_level(mp, VLF_FILE)));
        if (!mp->honor_rate_limits) {
            ds_put_cstr(&line, "    (rate limiting disabled)");
        }
        ds_put_char(&line, '\n');

        svec_add_nocopy(&lines, ds_steal_cstr(&line));
    }
    ovs_mutex_unlock(&log_file_mutex);

    svec_sort(&lines);

    char *line;
    SVEC_FOR_EACH (i, line, &lines) {
        ds_put_cstr(&s, line);
    }
    svec_destroy(&lines);

    return ds_cstr(&s);
}

/* Returns as a string current logging patterns for each destination.
 * This string must be released by caller. */
char *
vlog_get_patterns(void)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    enum vlog_destination destination;

    ovs_rwlock_rdlock(&pattern_rwlock);
    ds_put_format(&ds, "         prefix                            format\n");
    ds_put_format(&ds, "         ------                            ------\n");

    for (destination = 0; destination < VLF_N_DESTINATIONS; destination++) {
        struct destination *f = &destinations[destination];
        const char *prefix = "none";

        if (destination == VLF_SYSLOG && syslogger) {
            prefix = syslog_get_prefix(syslogger);
        }
        ds_put_format(&ds, "%-7s  %-32s  %s\n", f->name, prefix, f->pattern);
    }
    ovs_rwlock_unlock(&pattern_rwlock);

    return ds_cstr(&ds);
}

/* Returns true if a log message emitted for the given 'module' and 'level'
 * would cause some log output, false if that module and level are completely
 * disabled. */
bool
vlog_is_enabled(const struct vlog_module *module, enum vlog_level level)
{
    return module->min_level >= level;
}

//如果p以'{'开头，则'}'之前的内容将被写入到out中，最大写入out_size个字节
//否则def的内容将被写入到out中
static const char *
fetch_braces(const char *p, const char *def, char *out, size_t out_size/*out buffer的长度*/)
{
    if (*p == '{') {
        //'{' 与'}'符号之间的长度
        size_t n = strcspn(p + 1, "}");
        //可写入的最大数目
        size_t n_copy = MIN(n, out_size - 1);
        //将'{' ，'}'之间的内容，写入到out中
        memcpy(out, p + 1, n_copy);
        out[n_copy] = '\0';
        //跳过'{','}'及其中间内容
        p += n + 2;
    } else {
        //没有遇到'{',原样输出def到out中
        ovs_strlcpy(out, def, out_size);
    }
    return p;
}

static void
format_log_message(const struct vlog_module *module/*模块名称*/, enum vlog_level level/*日志级别*/,
                   const char *pattern/*前缀格式化形式*/, const char *message/*日志格式化串*/,
                   va_list args_/*日志参数*/, struct ds *s/*存放格式化后的串*/)
{
    char tmp[128];
    va_list args;
    const char *p;
    int facility;

    ds_clear(s);
    for (p = pattern; *p != '\0'; ) {
        const char *subprogram_name;
        enum { LEFT, RIGHT } justify = RIGHT;
        int pad = ' ';
        size_t length, field, used;

        if (*p != '%') {
            //未遇到'%'前，原样输出
            ds_put_char(s, *p++);
            continue;
        }

        //跳过遇到的'%'号
        p++;
        if (*p == '-') {
            //遇到’-‘,认为左对齐
            justify = LEFT;
            p++;
        }
        //遇到’0‘认为pad为’0‘
        if (*p == '0') {
            pad = '0';
            p++;
        }
        //如果接下来遇到的是数字，则其指定的为域宽度
        field = 0;
        while (isdigit((unsigned char)*p)) {
            field = (field * 10) + (*p - '0');
            p++;
        }

        //buffer的当前长度
        length = s->length;
        switch (*p++) {
        case 'A':
            //%A被解释为存放进程名称
            ds_put_cstr(s, program_name);
            break;
        case 'B':
            //%B被解释为？？？
            atomic_read_explicit(&log_facility, &facility,
                                 memory_order_relaxed);
            facility = facility ? facility : LOG_LOCAL0;
            ds_put_format(s, "%d", facility + syslog_levels[level]);
            break;
        case 'c':
            //%c{xxxx}中的xxx记录在tmp中
            p = fetch_braces(p, "", tmp, sizeof tmp);
            //%c被解释为存放模块名称
            ds_put_cstr(s, vlog_get_module_name(module));
            break;
        case 'd':
            //%d被解释为存放当前时间，%d后面的'{'，'}'之间的内容存放的是时间的格式化符号
            p = fetch_braces(p, "%Y-%m-%d %H:%M:%S.###", tmp, sizeof tmp);
            ds_put_strftime_msec(s, tmp, time_wall_msec(), false);
            break;
        case 'D':
            //%d等同于%d,使用utc时间
            p = fetch_braces(p, "%Y-%m-%d %H:%M:%S.###", tmp, sizeof tmp);
            ds_put_strftime_msec(s, tmp, time_wall_msec(), true);
            break;
        case 'E':
            //%E被解释为主机名称
            gethostname(tmp, sizeof tmp);
            tmp[sizeof tmp - 1] = '\0';
            ds_put_cstr(s, tmp);
            break;
        case 'm':
            //%m 被解析为用户的message信息输出
            /* Format user-supplied log message and trim trailing new-lines. */
            length = s->length;
            va_copy(args, args_);
            ds_put_format_valist(s, message, args);
            va_end(args);
            while (s->length > length && s->string[s->length - 1] == '\n') {
                s->length--;
            }
            break;
        case 'N':
            //%N 被解释为message编号
            ds_put_format(s, "%u", *msg_num_get_unsafe());
            break;
        case 'n':
            //%n 被解析为添加'\n'
            ds_put_char(s, '\n');
            break;
        case 'p':
            //%p 被解释为添加level名称
            ds_put_cstr(s, vlog_get_level_name(level));
            break;
        case 'P':
            //%P 被解释为添加父pid
            ds_put_format(s, "%ld", (long int) getpid());
            break;
        case 'r':
            //%r 被解析进程启动时间
            ds_put_format(s, "%lld", time_msec() - time_boot_msec());
            break;
        case 't':
            //%t 被解析为子进程名称
            subprogram_name = get_subprogram_name();
            ds_put_cstr(s, subprogram_name[0] ? subprogram_name : "main");
            break;
        case 'T':
            //%T 被解析为子进程名称，考虑了NULL情况
            subprogram_name = get_subprogram_name();
            if (subprogram_name[0]) {
                ds_put_format(s, "(%s)", subprogram_name);
            }
            break;
        default:
            //其它的原样输出
            ds_put_char(s, p[-1]);
            break;
        }
        //处理对齐及padding相关事项
        used = s->length - length;
        if (used < field) {
            size_t n_pad = field - used;
            if (justify == RIGHT) {
                ds_put_uninit(s, n_pad);
                memmove(&s->string[length + n_pad], &s->string[length], used);
                memset(&s->string[length], pad, n_pad);
            } else {
                ds_put_char_multiple(s, pad, n_pad);
            }
        }
    }
}

/* Exports the given 'syslog_message' to the configured udp syslog sink. */
static void
send_to_syslog_fd(const char *s, size_t length)
    OVS_REQ_RDLOCK(pattern_rwlock)
{
    static size_t max_length = SIZE_MAX;
    size_t send_len = MIN(length, max_length);

    while (write(syslog_fd, s, send_len) < 0 && errno == EMSGSIZE) {
        send_len -= send_len / 20;
        max_length = send_len;
    }
}

/* Writes 'message' to the log at the given 'level' and as coming from the
 * given 'module'.
 *
 * Guaranteed to preserve errno. */
//通过level级别输出message
void
vlog_valist(const struct vlog_module *module, enum vlog_level level/*日志级别*/,
            const char *message, va_list args)
{
    //日志是否可以输出到console口
    bool log_to_console = module->levels[VLF_CONSOLE] >= level;
    //日志是否可以输出到syslog
    bool log_to_syslog = module->levels[VLF_SYSLOG] >= level;
    bool log_to_file = module->levels[VLF_FILE]  >= level;

    if (!(log_to_console || log_to_syslog || log_to_file)) {
        /* fast path - all logging levels specify no logging, no
         * need to hog the log mutex
         */
        return;
    }

    ovs_mutex_lock(&log_file_mutex);
    //日志是否可以输出到file
    log_to_file &= (log_fd >= 0);
    ovs_mutex_unlock(&log_file_mutex);

    //任意一种方式可输出，则进入
    if (log_to_console || log_to_syslog || log_to_file) {
        int save_errno = errno;
        struct ds s;

        vlog_init();

        ds_init(&s);
        ds_reserve(&s, 1024);
        //增加消息id号
        ++*msg_num_get();

        ovs_rwlock_rdlock(&pattern_rwlock);
        if (log_to_console) {
            //输出到console口
            format_log_message(module, level,
                               destinations[VLF_CONSOLE].pattern, message,
                               args, &s);
            ds_put_char(&s, '\n');
            fputs(ds_cstr(&s), stderr);
        }

        if (log_to_syslog) {
            //输出到syslog
            int syslog_level = syslog_levels[level];
            char *save_ptr = NULL;
            char *line;
            int facility;

            format_log_message(module, level, destinations[VLF_SYSLOG].pattern,
                               message, args, &s);
            for (line = strtok_r(s.string, "\n", &save_ptr); line;
                 line = strtok_r(NULL, "\n", &save_ptr)) {
                atomic_read_explicit(&log_facility, &facility,
                                     memory_order_relaxed);
                syslogger->class->syslog(syslogger, syslog_level|facility, line);
            }

            if (syslog_fd >= 0) {
                format_log_message(module, level,
                                   "<%B>1 %D{%Y-%m-%dT%H:%M:%S.###Z} "
                                   "%E %A %P %c - \xef\xbb\xbf%m",
                                   message, args, &s);
                send_to_syslog_fd(ds_cstr(&s), s.length);
            }
        }

        if (log_to_file) {
            //输出到文件
            format_log_message(module, level, destinations[VLF_FILE].pattern,
                               message, args, &s);
            ds_put_char(&s, '\n');

            ovs_mutex_lock(&log_file_mutex);
            if (log_fd >= 0) {
                if (log_writer) {
                    async_append_write(log_writer, s.string, s.length);
                    if (level == VLL_EMER) {
                        async_append_flush(log_writer);
                    }
                } else {
                    ignore(write(log_fd, s.string, s.length));
                }
            }
            ovs_mutex_unlock(&log_file_mutex);
        }
        ovs_rwlock_unlock(&pattern_rwlock);

        ds_destroy(&s);
        errno = save_errno;
    }
}

//日志输出
void
vlog(const struct vlog_module *module/*日志所属模块*/, enum vlog_level level/*日志级别*/,
     const char *message/*格式化参数*/, ...)
{
    va_list args;

    va_start(args, message);
    vlog_valist(module, level, message, args);
    va_end(args);
}

/* Logs 'message' to 'module' at maximum verbosity, then exits with a failure
 * exit code.  Always writes the message to stderr, even if the console
 * destination is disabled.
 *
 * Choose this function instead of vlog_abort_valist() if the daemon monitoring
 * facility shouldn't automatically restart the current daemon.  */
void
vlog_fatal_valist(const struct vlog_module *module_,
                  const char *message, va_list args)
{
    struct vlog_module *module = CONST_CAST(struct vlog_module *, module_);

    /* Don't log this message to the console to avoid redundancy with the
     * message written by the later ovs_fatal_valist(). */
    module->levels[VLF_CONSOLE] = VLL_OFF;

    vlog_valist(module, VLL_EMER, message, args);
    ovs_fatal_valist(0, message, args);
}

/* Logs 'message' to 'module' at maximum verbosity, then exits with a failure
 * exit code.  Always writes the message to stderr, even if the console
 * destination is disabled.
 *
 * Choose this function instead of vlog_abort() if the daemon monitoring
 * facility shouldn't automatically restart the current daemon.  */
void
vlog_fatal(const struct vlog_module *module, const char *message, ...)
{
    va_list args;

    va_start(args, message);
    vlog_fatal_valist(module, message, args);
    va_end(args);
}

/* Logs 'message' to 'module' at maximum verbosity, then calls abort().  Always
 * writes the message to stderr, even if the console destination is disabled.
 *
 * Choose this function instead of vlog_fatal_valist() if the daemon monitoring
 * facility should automatically restart the current daemon.  */
void
vlog_abort_valist(const struct vlog_module *module_,
                  const char *message, va_list args)
{
    struct vlog_module *module = (struct vlog_module *) module_;

    /* Don't log this message to the console to avoid redundancy with the
     * message written by the later ovs_abort_valist(). */
    module->levels[VLF_CONSOLE] = VLL_OFF;

    vlog_valist(module, VLL_EMER, message, args);
    ovs_abort_valist(0, message, args);
}

/* Logs 'message' to 'module' at maximum verbosity, then calls abort().  Always
 * writes the message to stderr, even if the console destination is disabled.
 *
 * Choose this function instead of vlog_fatal() if the daemon monitoring
 * facility should automatically restart the current daemon.  */
void
vlog_abort(const struct vlog_module *module, const char *message, ...)
{
    va_list args;

    va_start(args, message);
    vlog_abort_valist(module, message, args);
    va_end(args);
}

//检查日志是否超限
bool
vlog_should_drop(const struct vlog_module *module, enum vlog_level level,
                 struct vlog_rate_limit *rl)
{
    if (!module->honor_rate_limits) {
    	//日志限速功能关闭，不丢日志
        return false;
    }

    if (!vlog_is_enabled(module, level)) {
    	//此模块日志level未开启
        return true;
    }

    ovs_mutex_lock(&rl->mutex);
    if (!token_bucket_withdraw(&rl->token_bucket, VLOG_MSG_TOKENS)) {
    	//token不足，丢日志
        time_t now = time_now();
        if (!rl->n_dropped) {
            rl->first_dropped = now;
        }
        rl->last_dropped = now;
        rl->n_dropped++;
        ovs_mutex_unlock(&rl->mutex);
        return true;
    }

    if (!rl->n_dropped) {
        ovs_mutex_unlock(&rl->mutex);
    } else {
        time_t now = time_now();
        unsigned int n_dropped = rl->n_dropped;
        unsigned int first_dropped_elapsed = now - rl->first_dropped;
        unsigned int last_dropped_elapsed = now - rl->last_dropped;
        rl->n_dropped = 0;
        ovs_mutex_unlock(&rl->mutex);

        //指明下面的日志丢包好多次
        vlog(module, level,
             "Dropped %u log messages in last %u seconds (most recently, "
             "%u seconds ago) due to excessive rate",
             n_dropped, first_dropped_elapsed, last_dropped_elapsed);
    }

    return false;
}

//速率日志
void
vlog_rate_limit(const struct vlog_module *module, enum vlog_level level,
                struct vlog_rate_limit *rl, const char *message, ...)
{
    if (!vlog_should_drop(module, level, rl)) {
        va_list args;

        va_start(args, message);
        vlog_valist(module, level, message, args);
        va_end(args);
    }
}

void
vlog_usage(void)
{
    printf("\n\
Logging options:\n\
  -vSPEC, --verbose=SPEC   set logging levels\n\
  -v, --verbose            set maximum verbosity level\n\
  --log-file[=FILE]        enable logging to specified FILE\n\
                           (default: %s/%s.log)\n\
  --syslog-method=(libc|unix:file|udp:ip:port)\n\
                           specify how to send messages to syslog daemon\n\
  --syslog-target=HOST:PORT  also send syslog msgs to HOST:PORT via UDP\n",
           ovs_logdir(), program_name);
}
