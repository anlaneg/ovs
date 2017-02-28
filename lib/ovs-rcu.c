/*
 * Copyright (c) 2014 Nicira, Inc.
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
#include "ovs-rcu.h"
#include "fatal-signal.h"
#include "guarded-list.h"
#include "openvswitch/list.h"
#include "ovs-thread.h"
#include "poll-loop.h"
#include "seq.h"
#include "timeval.h"
#include "util.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(ovs_rcu);

struct ovsrcu_cb {
    void (*function)(void *aux);
    void *aux;
};

struct ovsrcu_cbset {
    struct ovs_list list_node;
    struct ovsrcu_cb cbs[16];
    int n_cbs;
};

struct ovsrcu_perthread {
    struct ovs_list list_node;  /* In global list. */

    struct ovs_mutex mutex;
    uint64_t seqno;
    //各线程提交的回调
    struct ovsrcu_cbset *cbset;
    char name[16];              /* This thread's name. */
};

static struct seq *global_seqno;

//存储ovsrcu-thread的pthread-key
static pthread_key_t perthread_key;
//存储所有ovsrcu-thread
static struct ovs_list ovsrcu_threads;
//保护ovsrcu-threads锁
static struct ovs_mutex ovsrcu_threads_mutex;

//全局等待执行的cbsets，（在这个之前先在pthread中的cbset中保存）
static struct guarded_list flushed_cbsets;
//用于代表flushed_cbsets是否有变更
static struct seq *flushed_cbsets_seq;

static void ovsrcu_init_module(void);
static void ovsrcu_flush_cbset__(struct ovsrcu_perthread *, bool);
static void ovsrcu_flush_cbset(struct ovsrcu_perthread *);
static void ovsrcu_unregister__(struct ovsrcu_perthread *);
static bool ovsrcu_call_postponed(void);
static void *ovsrcu_postpone_thread(void *arg OVS_UNUSED);

//构造当前线程对应的ovsrcu-perthread
static struct ovsrcu_perthread *
ovsrcu_perthread_get(void)
{
    struct ovsrcu_perthread *perthread;

    ovsrcu_init_module();

    perthread = pthread_getspecific(perthread_key);
    if (!perthread) {
        const char *name = get_subprogram_name();

        perthread = xmalloc(sizeof *perthread);
        ovs_mutex_init(&perthread->mutex);
        perthread->seqno = seq_read(global_seqno);
        perthread->cbset = NULL;
        ovs_strlcpy(perthread->name, name[0] ? name : "main",
                    sizeof perthread->name);

        ovs_mutex_lock(&ovsrcu_threads_mutex);
        ovs_list_push_back(&ovsrcu_threads, &perthread->list_node);
        ovs_mutex_unlock(&ovsrcu_threads_mutex);

        pthread_setspecific(perthread_key, perthread);
    }
    return perthread;
}

/* Indicates the end of a quiescent state.  See "Details" near the top of
 * ovs-rcu.h.
 *
 * Quiescent states don't stack or nest, so this always ends a quiescent state
 * even if ovsrcu_quiesce_start() was called multiple times in a row. */
//获取perthread
void
ovsrcu_quiesce_end(void)
{
    ovsrcu_perthread_get();
}

//对单线程而言，再调一次postponed(刚才可能由thread->cbset刷入到flushed_cbset),可以直接执行
//对多线程而言，需要保证postpone_thead线程已启动
static void
ovsrcu_quiesced(void)
{
    if (single_threaded()) {
        ovsrcu_call_postponed();
    } else {
        static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;
        if (ovsthread_once_start(&once)) {
        	//创建urcu线程
            ovs_thread_create("urcu", ovsrcu_postpone_thread, NULL);
            ovsthread_once_done(&once);
        }
    }
}

/* Indicates the beginning of a quiescent state.  See "Details" near the top of
 * ovs-rcu.h. */
//如果自已有cbset,则将自已的cbset放入到flushed_cbset中，并将自身销毁
//单线程尝试执行，多线程确保rcu回调线程存在
void
ovsrcu_quiesce_start(void)
{
    struct ovsrcu_perthread *perthread;

    ovsrcu_init_module();
    perthread = pthread_getspecific(perthread_key);
    if (perthread) {
        pthread_setspecific(perthread_key, NULL);
        ovsrcu_unregister__(perthread);
    }

    ovsrcu_quiesced();
}

/* Indicates a momentary quiescent state.  See "Details" near the top of
 * ovs-rcu.h.
 *
 * Provides a full memory barrier via seq_change().
 */
//更新当前perthread的序号，如果有cbset存在，则flush它
//更新global_seqno
void
ovsrcu_quiesce(void)
{
    struct ovsrcu_perthread *perthread;

    perthread = ovsrcu_perthread_get();
    //系统变更seqno处（１）
    perthread->seqno = seq_read(global_seqno);
    if (perthread->cbset) {
        ovsrcu_flush_cbset(perthread);
    }
    seq_change(global_seqno);

    ovsrcu_quiesced();
}

//尝试加锁，并更新perthread->seqno,将perthread->cbset刷入到flushed_cbsets
//更新global_seqno
int
ovsrcu_try_quiesce(void)
{
    struct ovsrcu_perthread *perthread;
    int ret = EBUSY;

    ovs_assert(!single_threaded());
    perthread = ovsrcu_perthread_get();
    if (!seq_try_lock()) {
        //系统变更seqno处（１）
        perthread->seqno = seq_read_protected(global_seqno);
        if (perthread->cbset) {
        	//如果有回调集，就将其刷入到flushed_cbsets
            ovsrcu_flush_cbset__(perthread, true);
        }
        seq_change_protected(global_seqno);
        seq_unlock();
        ovsrcu_quiesced();
        ret = 0;
    }
    return ret;
}

//检查ovsrcu_pthread是否为NULL
bool
ovsrcu_is_quiescent(void)
{
    ovsrcu_init_module();
    return pthread_getspecific(perthread_key) == NULL;
}

//同步代码，等待所有seq满足，将其刷入
void
ovsrcu_synchronize(void)
{
    unsigned int warning_threshold = 1000;
    uint64_t target_seqno;
    long long int start;

    if (single_threaded()) {
        return;
    }

    target_seqno = seq_read(global_seqno);
    ovsrcu_quiesce_start();//将当前线程刷入，并销毁当前线程的记录
    start = time_msec();

    for (;;) {
        uint64_t cur_seqno = seq_read(global_seqno);
        struct ovsrcu_perthread *perthread;
        char stalled_thread[16];
        unsigned int elapsed;
        bool done = true;

        //加锁，检查是否所有线程的seqno是否都大于target_seqno,如果大于，则跳出此循环
        //否则一直等。
        ovs_mutex_lock(&ovsrcu_threads_mutex);
        LIST_FOR_EACH (perthread, list_node, &ovsrcu_threads) {
            if (perthread->seqno <= target_seqno) {
                ovs_strlcpy(stalled_thread, perthread->name,
                            sizeof stalled_thread);
                done = false;
                break;
            }
        }
        ovs_mutex_unlock(&ovsrcu_threads_mutex);

        if (done) {
            break;
        }

        //报警，指明等待超时
        elapsed = time_msec() - start;
        if (elapsed >= warning_threshold) {
            VLOG_WARN("blocked %u ms waiting for %s to quiesce",
                      elapsed, stalled_thread);
            warning_threshold *= 2;
        }
        poll_timer_wait_until(start + warning_threshold);

        seq_wait(global_seqno, cur_seqno);
        poll_block();
    }
    ovsrcu_quiesce_end();
}

/* Registers 'function' to be called, passing 'aux' as argument, after the
 * next grace period.
 *
 * The call is guaranteed to happen after the next time all participating
 * threads have quiesced at least once, but there is no quarantee that all
 * registered functions are called as early as possible, or that the functions
 * registered by different threads would be called in the order the
 * registrations took place.  In particular, even if two threads provably
 * register a function each in a specific order, the functions may still be
 * called in the opposite order, depending on the timing of when the threads
 * call ovsrcu_quiesce(), how many functions they postpone, and when the
 * ovs-rcu thread happens to grab the functions to be called.
 *
 * All functions registered by a single thread are guaranteed to execute in the
 * registering order, however.
 *
 * This function is more conveniently called through the ovsrcu_postpone()
 * macro, which provides a type-safe way to allow 'function''s parameter to be
 * any pointer type. */
//向里面添加cbset
void
ovsrcu_postpone__(void (*function)(void *aux), void *aux)
{
	//将function加入到cbset中，如果cbset已满，则直接唤醒，要求执行
    struct ovsrcu_perthread *perthread = ovsrcu_perthread_get();
    struct ovsrcu_cbset *cbset;
    struct ovsrcu_cb *cb;

    cbset = perthread->cbset;
    if (!cbset) {
        cbset = perthread->cbset = xmalloc(sizeof *perthread->cbset);
        cbset->n_cbs = 0;
    }

    cb = &cbset->cbs[cbset->n_cbs++];
    cb->function = function;
    cb->aux = aux;

    if (cbset->n_cbs >= ARRAY_SIZE(cbset->cbs)) {
        ovsrcu_flush_cbset(perthread);
    }
}

//执行所有回调集
static bool
ovsrcu_call_postponed(void)
{
    struct ovsrcu_cbset *cbset;
    struct ovs_list cbsets;

    guarded_list_pop_all(&flushed_cbsets, &cbsets);
    if (ovs_list_is_empty(&cbsets)) {
    	//没有回调集，退
        return false;
    }

    //阻塞等待执行条件满足
    ovsrcu_synchronize();

    //执行所有回调集
    LIST_FOR_EACH_POP (cbset, list_node, &cbsets) {
        struct ovsrcu_cb *cb;

        for (cb = cbset->cbs; cb < &cbset->cbs[cbset->n_cbs]; cb++) {
            cb->function(cb->aux);
        }
        free(cbset);
    }

    return true;
}
//监控flushed_cbsets_seq,如果其发生变化，则执行相应回调
static void *
ovsrcu_postpone_thread(void *arg OVS_UNUSED)
{
    pthread_detach(pthread_self());

    for (;;) {
        uint64_t seqno = seq_read(flushed_cbsets_seq);
        //尝试执行所有flushed_cbsets
        if (!ovsrcu_call_postponed()) {
        	//如果没有cbsets，则等待，直到flushed_cbsets_seq改变
            seq_wait(flushed_cbsets_seq, seqno);
            poll_block();
        }
    }

    OVS_NOT_REACHED();
}

static void
ovsrcu_flush_cbset__(struct ovsrcu_perthread *perthread, bool protected)
{
    struct ovsrcu_cbset *cbset = perthread->cbset;

    if (cbset) {
    	//各线程将由mutex保护下，向flushed_cbsets中提交自已的cbset
        guarded_list_push_back(&flushed_cbsets, &cbset->list_node, SIZE_MAX);
        perthread->cbset = NULL;

        //如果seq已被保护，则不需要再加锁
        if (protected) {
            seq_change_protected(flushed_cbsets_seq);
        } else {
            seq_change(flushed_cbsets_seq);
        }
    }
}

//向下刷cbset(flushed_cbsets_seq未保护）
static void
ovsrcu_flush_cbset(struct ovsrcu_perthread *perthread)
{
    ovsrcu_flush_cbset__(perthread, false);
}

//释放perthread
static void
ovsrcu_unregister__(struct ovsrcu_perthread *perthread)
{
    if (perthread->cbset) {
    	//有回调集，刷下去
        ovsrcu_flush_cbset(perthread);
    }

    ovs_mutex_lock(&ovsrcu_threads_mutex);
    ovs_list_remove(&perthread->list_node);
    ovs_mutex_unlock(&ovsrcu_threads_mutex);

    ovs_mutex_destroy(&perthread->mutex);
    free(perthread);

    seq_change(global_seqno);
}

static void
ovsrcu_thread_exit_cb(void *perthread)
{
	//释放perthread
    ovsrcu_unregister__(perthread);
}

/* Cancels the callback to ovsrcu_thread_exit_cb().
 *
 * Cancelling the call to the destructor during the main thread exit
 * is needed while using pthreads-win32 library in Windows. It has been
 * observed that in pthreads-win32, a call to the destructor during
 * main thread exit causes undefined behavior. */
static void
ovsrcu_cancel_thread_exit_cb(void *aux OVS_UNUSED)
{
	//清空perthread_key对应的值
    pthread_setspecific(perthread_key, NULL);
}

//模块初始化
static void
ovsrcu_init_module(void)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;
    if (ovsthread_once_start(&once)) {
        global_seqno = seq_create();
        xpthread_key_create(&perthread_key, ovsrcu_thread_exit_cb);
        fatal_signal_add_hook(ovsrcu_cancel_thread_exit_cb, NULL, NULL, true);
        ovs_list_init(&ovsrcu_threads);
        ovs_mutex_init(&ovsrcu_threads_mutex);

        guarded_list_init(&flushed_cbsets);
        flushed_cbsets_seq = seq_create();

        ovsthread_once_done(&once);
    }
}
