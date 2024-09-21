/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013 Nicira, Inc.
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
#include "backtrace.h"
#include "fatal-signal.h"
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "ovs-thread.h"
#include "openvswitch/poll-loop.h"
#include "openvswitch/shash.h"
#include "sset.h"
#include "signals.h"
#include "socket-util.h"
#include "util.h"
#include "openvswitch/vlog.h"

#include "openvswitch/type-props.h"

#ifdef HAVE_UNWIND
#include "daemon-private.h"
#endif

#ifndef SIG_ATOMIC_MAX
#define SIG_ATOMIC_MAX TYPE_MAXIMUM(sig_atomic_t)
#endif

VLOG_DEFINE_THIS_MODULE(fatal_signal);

//此文件就是一个信号处理方式，将关注的信号转变成fd通知，然后在收到fd通知后
//可以调用hook,比如exit时删除文件啊，这类操作

/* Signals to catch. */
#ifndef _WIN32
//需要关注的信号
static const int fatal_signals[] = { SIGTERM, SIGINT, SIGHUP, SIGALRM,
                                     SIGSEGV };
#else
static const int fatal_signals[] = { SIGTERM };
#endif

/* Hooks to call upon catching a signal */
struct hook {
    void (*hook_cb)(void *aux);//信号发生时的回调
    void (*cancel_cb)(void *aux);//信号取消时的回调
    void *aux;
    bool run_at_exit;//是否在退出时调用
};
#define MAX_HOOKS 32
static struct hook hooks[MAX_HOOKS];
static size_t n_hooks;

static int signal_fds[2];//信号管道
static volatile sig_atomic_t stored_sig_nr = SIG_ATOMIC_MAX;//存储收到的信号

#ifdef _WIN32
static HANDLE wevent;
#endif

static struct ovs_mutex mutex;

static void call_hooks(int sig_nr);
#ifdef _WIN32
static BOOL WINAPI ConsoleHandlerRoutine(DWORD dwCtrlType);
#endif

/* Initializes the fatal signal handling module.  Calling this function is
 * optional, because calling any other function in the module will also
 * initialize it.  However, in a multithreaded program, the module must be
 * initialized while the process is still single-threaded. */
//信号处理回调注册，通过函数fatal_signal_handler，将信号触发变更为
//fd（signal_fds[1]负责通知触发信号，signal_fds[0]负责读）通知
void
fatal_signal_init(void)
{
    static bool inited = false;

    if (!inited) {
        size_t i;

        //未初始化情况下，必须为单线程，开始执行信息处理句柄初始化
        assert_single_threaded();
        inited = true;

        ovs_mutex_init_recursive(&mutex);
#ifndef _WIN32
        //产生信号fds,并置为非阻塞
        xpipe_nonblocking(signal_fds);
#else
        wevent = CreateEvent(NULL, TRUE, FALSE, NULL);
        if (!wevent) {
            char *msg_buf = ovs_lasterror_to_string();
            VLOG_FATAL("Failed to create a event (%s).", msg_buf);
        }

        /* Register a function to handle Ctrl+C. */
        SetConsoleCtrlHandler(ConsoleHandlerRoutine, true);
#endif

        //遍历处理需要关注的信息，为它们注册回调
        for (i = 0; i < ARRAY_SIZE(fatal_signals); i++) {
            int sig_nr = fatal_signals[i];
#ifndef _WIN32
            struct sigaction old_sa;

            //取此信号系统当前提供的默认处理处理函数，如果为DEF函数，则为其
            //注册fatal_signal_handler
            xsigaction(sig_nr, NULL, &old_sa);
            if (old_sa.sa_handler == SIG_DFL
                && signal(sig_nr, fatal_signal_handler) == SIG_ERR) {
            	//如果未注册处理句柄，注册处理函数为fatal_signal_handler
                VLOG_FATAL("signal failed (%s)", ovs_strerror(errno));
            }
#else
            if (signal(sig_nr, fatal_signal_handler) == SIG_ERR) {
                VLOG_FATAL("signal failed (%s)", ovs_strerror(errno));
            }
#endif
        }
        //注册进程退出时，执行函数fatal_signal_atexit_handler
        atexit(fatal_signal_atexit_handler);
    }
}

/* Registers 'hook_cb' to be called from inside poll_block() following a fatal
 * signal.  'hook_cb' does not need to be async-signal-safe.  In a
 * multithreaded program 'hook_cb' might be called from any thread, with
 * threads other than the one running 'hook_cb' in unknown states.
 *
 * If 'run_at_exit' is true, 'hook_cb' is also called during normal process
 * termination, e.g. when exit() is called or when main() returns.
 *
 * If the current process forks, fatal_signal_fork() may be called to clear the
 * parent process's fatal signal hooks, so that 'hook_cb' is only called when
 * the child terminates, not when the parent does.  When fatal_signal_fork() is
 * called, it calls the 'cancel_cb' function if it is nonnull, passing 'aux',
 * to notify that the hook has been canceled.  This allows the hook to free
 * memory, etc. */
void
//添加相应的hook
fatal_signal_add_hook(void (*hook_cb)(void *aux), void (*cancel_cb)(void *aux),
                      void *aux, bool run_at_exit)
{
    fatal_signal_init();

    ovs_mutex_lock(&mutex);
    ovs_assert(n_hooks < MAX_HOOKS);
    hooks[n_hooks].hook_cb = hook_cb;
    hooks[n_hooks].cancel_cb = cancel_cb;
    hooks[n_hooks].aux = aux;
    hooks[n_hooks].run_at_exit = run_at_exit;
    n_hooks++;
    ovs_mutex_unlock(&mutex);
}

#ifdef HAVE_UNWIND
/* Convert unsigned long long to string.  This is needed because
 * using snprintf() is not async signal safe. */
static inline int
llong_to_hex_str(unsigned long long value, char *str)
{
    int i = 0, res;

    if (value / 16 > 0) {
        i = llong_to_hex_str(value / 16, str);
    }

    res = value % 16;
    str[i] = "0123456789abcdef"[res];

    return i + 1;
}

/* Send the backtrace buffer to monitor thread.
 *
 * Note that this runs in the signal handling context, any system
 * library functions used here must be async-signal-safe.
 */
static inline void
send_backtrace_to_monitor(void) {
    /* volatile added to prevent a "clobbered" error on ppc64le with gcc */
    volatile int dep;
    struct unw_backtrace unw_bt[UNW_MAX_DEPTH];
    unw_cursor_t cursor;
    unw_context_t uc;

    if (daemonize_fd == -1) {
        return;
    }

    dep = 0;
    unw_getcontext(&uc);
    unw_init_local(&cursor, &uc);

    while (dep < UNW_MAX_DEPTH && unw_step(&cursor)) {
        memset(unw_bt[dep].func, 0, UNW_MAX_FUNCN);
        unw_get_reg(&cursor, UNW_REG_IP, &unw_bt[dep].ip);
        unw_get_proc_name(&cursor, unw_bt[dep].func, UNW_MAX_FUNCN,
                          &unw_bt[dep].offset);
        dep++;
    }

    if (monitor) {
        ignore(write(daemonize_fd, unw_bt,
                     dep * sizeof(struct unw_backtrace)));
    } else {
        /* Since there is no monitor daemon running, write backtrace
         * in current process.
         */
        char str[] = "SIGSEGV detected, backtrace:\n";
        char ip_str[16], offset_str[6];
        char line[64], fn_name[UNW_MAX_FUNCN];

        vlog_direct_write_to_log_file_unsafe(str);

        for (int i = 0; i < dep; i++) {
            memset(line, 0, sizeof line);
            memset(fn_name, 0, sizeof fn_name);
            memset(offset_str, 0, sizeof offset_str);
            memset(ip_str, ' ', sizeof ip_str);
            ip_str[sizeof(ip_str) - 1] = 0;

            llong_to_hex_str(unw_bt[i].ip, ip_str);
            llong_to_hex_str(unw_bt[i].offset, offset_str);

            strcat(line, "0x");
            strcat(line, ip_str);
            strcat(line, "<");
            memcpy(fn_name, unw_bt[i].func, UNW_MAX_FUNCN - 1);
            strcat(line, fn_name);
            strcat(line, "+0x");
            strcat(line, offset_str);
            strcat(line, ">\n");
            vlog_direct_write_to_log_file_unsafe(line);
        }
    }
}
#else
static inline void
send_backtrace_to_monitor(void) {
    /* Nothing. */
}
#endif

/* Handles fatal signal number 'sig_nr'.
 *
 * Ordinarily this is the actual signal handler.  When other code needs to
 * handle one of our signals, however, it can register for that signal and, if
 * and when necessary, call this function to do fatal signal processing for it
 * and terminate the process.  Currently only timeval.c does this, for SIGALRM.
 * (It is not important whether the other code sets up its signal handler
 * before or after this file, because this file will only set up a signal
 * handler in the case where the signal has its default handling.)  */
void
fatal_signal_handler(int sig_nr)//信号处理
{
#ifndef _WIN32
    if (sig_nr == SIGSEGV) {
        /*针对SIGSEGV，立即处理*/
        signal(sig_nr, SIG_DFL); /* Set it back immediately. */
        send_backtrace_to_monitor();
        raise(sig_nr);
    }
	//向管道中发消息，知会收到信号
    ignore(write(signal_fds[1], "", 1));
#else
    SetEvent(wevent);
#endif
    /*保存收到的信号*/
    stored_sig_nr = sig_nr;
}

/* Check whether a fatal signal has occurred and, if so, call the fatal signal
 * hooks and exit.
 *
 * This function is called automatically by poll_block(), but specialized
 * programs that may not always call poll_block() on a regular basis should
 * also call it periodically.  (Therefore, any function with "block" in its
 * name should call fatal_signal_run() each time it is called, either directly
 * or through poll_block(), because such functions can only used by specialized
 * programs that can afford to block outside their main loop around
 * poll_block().)
 */
void
fatal_signal_run(void)
{
    sig_atomic_t sig_nr;

    /*运行一次，注册信号*/
    fatal_signal_init();

    /*取收到的被缓存的信号*/
    sig_nr = stored_sig_nr;
    if (sig_nr != SIG_ATOMIC_MAX) {
        char namebuf[SIGNAL_NAME_BUFSIZE];

        ovs_mutex_lock(&mutex);

#ifndef _WIN32
        VLOG_WARN("terminating with signal %d (%s)",
                  (int)sig_nr, signal_name(sig_nr, namebuf, sizeof namebuf));
#else
        VLOG_WARN("terminating with signal %d", (int)sig_nr);
#endif
        //针对此信号调回调
        call_hooks(sig_nr);
        fflush(stderr);

        /* Re-raise the signal with the default handling so that the program
         * termination status reflects that we were killed by this signal */
        signal(sig_nr, SIG_DFL);//将此信号变更为默认处理形式
        raise(sig_nr);//再调用一次（程序将在此处挂掉）

        ovs_mutex_unlock(&mutex);
        OVS_NOT_REACHED();
    }
}

//使信号处理，支持poll
void
fatal_signal_wait(void)
{
	//将关注的signal注册到系统，并转变为signal_fds[0]的读事件
    fatal_signal_init();
#ifdef _WIN32
    poll_wevent_wait(wevent);
#else
    //注册信号signal_fds[0]的读事件，监听信号发生
    poll_fd_wait(signal_fds[0], POLLIN);
#endif
}

void
fatal_ignore_sigpipe(void)//忽略pipe信号
{
#ifndef _WIN32
    signal(SIGPIPE, SIG_IGN);
#endif
}

void
fatal_signal_atexit_handler(void)//进程退出时执行
{
    call_hooks(0);
}

//调用回调，如果sig_nr不为0，则调用所有hooks的hook_cb，如果为0，则仅调用exit时可调用的回调
static void
call_hooks(int sig_nr)
{
    static volatile sig_atomic_t recurse = 0;
    if (!recurse) {
        size_t i;

        recurse = 1;

        for (i = 0; i < n_hooks; i++) {
            struct hook *h = &hooks[i];
            if (sig_nr || h->run_at_exit) {
                h->hook_cb(h->aux);
            }
        }
    }
}

#ifdef _WIN32
BOOL WINAPI ConsoleHandlerRoutine(DWORD dwCtrlType)
{
    stored_sig_nr = SIGINT;
    SetEvent(wevent);
    return true;
}
#endif

/* Files to delete on exit. */
static struct sset files = SSET_INITIALIZER(&files);//记录在exit时，需要删除的文件

/* Has a hook function been registered with fatal_signal_add_hook() (and not
 * cleared by fatal_signal_fork())? */
static bool added_hook;//hook是否已添加

static void unlink_files(void *aux);
static void cancel_files(void *aux);
static void do_unlink_files(void);

/* Registers 'file' to be unlinked when the program terminates via exit() or a
 * fatal signal. */
void
fatal_signal_add_file_to_unlink(const char *file)//注册此文件在信号发生时的处理
{
    fatal_signal_init();

    ovs_mutex_lock(&mutex);
    if (!added_hook) {
        added_hook = true;
        fatal_signal_add_hook(unlink_files, cancel_files, NULL, true);//如果发生fork,files中内容需要清空
    }

    sset_add(&files, file);
    ovs_mutex_unlock(&mutex);
}

/* Unregisters 'file' from being unlinked when the program terminates via
 * exit() or a fatal signal. */
void
fatal_signal_remove_file_to_unlink(const char *file)//移除此文件在信号发生时的处理（注：不移除回调）
{
    fatal_signal_init();

    ovs_mutex_lock(&mutex);
    sset_find_and_delete(&files, file);
    ovs_mutex_unlock(&mutex);
}

/* Like fatal_signal_remove_file_to_unlink(), but also unlinks 'file'.
 * Returns 0 if successful, otherwise a positive errno value. */
int
fatal_signal_unlink_file_now(const char *file)//直接移除文件，而不必等待到信号发生时触发
{
    int error;

    fatal_signal_init();

    ovs_mutex_lock(&mutex);

    error = unlink(file) ? errno : 0;
    if (error) {
        VLOG_WARN("could not unlink \"%s\" (%s)", file, ovs_strerror(error));
    }

    fatal_signal_remove_file_to_unlink(file);

    ovs_mutex_unlock(&mutex);

    return error;
}

static void
unlink_files(void *aux OVS_UNUSED)//信号发生时的回调，处理删除文件操作
{
    do_unlink_files();
}

static void
cancel_files(void *aux OVS_UNUSED)//信号取消时的回调，请空files集合
{
    sset_clear(&files);
    added_hook = false;
}

static void
do_unlink_files(void)//删除files集合中的文件
{
    const char *file;

    SSET_FOR_EACH (file, &files) {
        unlink(file);
    }
}

/* Clears all of the fatal signal hooks without executing them.  If any of the
 * hooks passed a 'cancel_cb' function to fatal_signal_add_hook(), then those
 * functions will be called, allowing them to free resources, etc.
 *
 * Following a fork, one of the resulting processes can call this function to
 * allow it to terminate without calling the hooks registered before calling
 * this function.  New hooks registered after calling this function will take
 * effect normally. */
void
fatal_signal_fork(void)//清空信号处理回调，如果期间收到信号，触发信号
{
    size_t i;

    assert_single_threaded();

    for (i = 0; i < n_hooks; i++) {//清除掉所有注册的回调
        struct hook *h = &hooks[i];
        if (h->cancel_cb) {
            h->cancel_cb(h->aux);
        }
    }
    n_hooks = 0;

    /* Raise any signals that we have already received with the default
     * handler. */
    if (stored_sig_nr != SIG_ATOMIC_MAX) {
        raise(stored_sig_nr);
    }
}

#ifndef _WIN32
/* Blocks all fatal signals and returns previous signal mask into
 * 'prev_mask'. */
void
fatal_signal_block(sigset_t *prev_mask)//指定线程阻塞信号处理
{
    int i;
    sigset_t block_mask;

    sigemptyset(&block_mask);
    for (i = 0; i < ARRAY_SIZE(fatal_signals); i++) {
        int sig_nr = fatal_signals[i];
        sigaddset(&block_mask, sig_nr);
    }
    xpthread_sigmask(SIG_BLOCK, &block_mask, prev_mask);
}
#endif
