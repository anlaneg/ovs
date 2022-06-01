/*
 * Copyright (c) 2014, 2017 Nicira, Inc.
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
#include "latch.h"
#include "openvswitch/list.h"
#include "ovs-thread.h"
#include "openvswitch/poll-loop.h"
#include "seq.h"
#include "timeval.h"
#include "util.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(ovs_rcu);

#define MIN_CBS 16

struct ovsrcu_cb {
    void (*function)(void *aux);
    void *aux;
};

struct ovsrcu_cbset {
    struct ovs_list list_node;
    struct ovsrcu_cb *cbs;
    size_t n_allocated;
    int n_cbs;
};

struct ovsrcu_perthread {
    struct ovs_list list_node;  /* In global list. */

    /*当前线程的seq编号，用于确定当前线程编号与全局编号是否有差异*/
    uint64_t seqno;
    //各线程提交的回调
    struct ovsrcu_cbset *cbset;
    /*当前线程名称*/
    char name[16];              /* This thread's name. */
};

//全局的seq对象
static struct seq *global_seqno;

//存储ovsrcu-thread的pthread-key
static pthread_key_t perthread_key;
//存储所有ovsrcu-thread
static struct ovs_list ovsrcu_threads;
//保护ovsrcu-threads，采用此锁
static struct ovs_mutex ovsrcu_threads_mutex;

//全局等待执行的cbsets，（在存放到这个之前，先在pthread中的cbset中保存）
static struct guarded_list flushed_cbsets;
//用于代表flushed_cbsets是否有变更,此seq有变更，则等待此seq的就可被wakeup,然后执行相应回调集合
static struct seq *flushed_cbsets_seq;

static struct latch postpone_exit;
static struct ovs_barrier postpone_barrier;

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

    /*取当前线程的ovsrcu-perthread，如果其不存在，则创建它*/
    perthread = pthread_getspecific(perthread_key);
    if (!perthread) {
        //取当前线程名称
        const char *name = get_subprogram_name();

        perthread = xmalloc(sizeof *perthread);
        /*取全局seq中的序号,做为初始化*/
        perthread->seqno = seq_read(global_seqno);
        perthread->cbset = NULL;
        ovs_strlcpy(perthread->name, name[0] ? name : "main",
                    sizeof perthread->name);

        ovs_mutex_lock(&ovsrcu_threads_mutex);
        //增加已知的ovsrcu-perthread
        ovs_list_push_back(&ovsrcu_threads, &perthread->list_node);
        ovs_mutex_unlock(&ovsrcu_threads_mutex);

        pthread_setspecific(perthread_key, perthread);
    }

    /*如果已存在，则直接返回*/
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
	/*重新构造rcu需要的线程私有数据*/
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
            latch_init(&postpone_exit);
            ovs_barrier_init(&postpone_barrier, 2);
            //创建urcu线程，负责rcu回调执行
            ovs_thread_create("urcu", ovsrcu_postpone_thread, NULL);
            ovsthread_once_done(&once);
        }
    }
}

/* Indicates the beginning of a quiescent state.  See "Details" near the top of
 * ovs-rcu.h. */
//指明rcu空闲开始（即不会有人使用rcu回调对应的内存)
//此时如果自已有cbset,则会将自已的cbset放入到flushed_cbset中，并将自身内容销毁（此时没有人使用rcu)
//针对回调执行，单线程则直接执行，多线程则确保rcu回调线程存在
void
ovsrcu_quiesce_start(void)
{
    struct ovsrcu_perthread *perthread;

    ovsrcu_init_module();
    perthread = pthread_getspecific(perthread_key);
    if (perthread) {
    	//当前线程有rcu私有key,将私有key移除掉，执行注册的相应回调
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
//更新当前thread的seqno，如果当前线程有cbset存在，则flush它到全局cbset,并唤醒waiter进行执行
//另外更新系统全局的seq: global_seqno
void
ovsrcu_quiesce(void)
{
    struct ovsrcu_perthread *perthread;

    perthread = ovsrcu_perthread_get();
    //变更本线程的seqno
    perthread->seqno = seq_read(global_seqno);

    //如果本线程有cbset，则提交cbset给waiter进行执行
    if (perthread->cbset) {
        ovsrcu_flush_cbset(perthread);
    }

    //变更系统全局seqno处（１）
    seq_change(global_seqno);

    ovsrcu_quiesced();
}

//尝试加锁，如果加锁成功，则更新perthread->seqno,并将perthread->cbset刷入到flushed_cbsets，
//通知waiter准备处理回调函数，并更新global_seqno
int
ovsrcu_try_quiesce(void)
{
    struct ovsrcu_perthread *perthread;
    int ret = EBUSY;

    ovs_assert(!single_threaded());
    perthread = ovsrcu_perthread_get();
    if (!seq_try_lock()) {
        //更新当前线程的seq为系统seqno
        perthread->seqno = seq_read_protected(global_seqno);
        if (perthread->cbset) {
        	//如果有回调集，就将其刷入到flushed_cbsets
            ovsrcu_flush_cbset__(perthread, true);
        }

        //变更系统全局seqno处（2）
        seq_change_protected(global_seqno);
        seq_unlock();
        //如果是多线程，则什么也不做（初始化urcu线程只做一次）
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

//rcu同步代码，等待所有seq满足，将其刷入
void
ovsrcu_synchronize(void)
{
    unsigned int warning_threshold = 1000;
    uint64_t target_seqno;
    long long int start;

    if (single_threaded()) {
    	//单线程情况，不用等
        return;
    }

    /*读系统当前的全局seq*/
    target_seqno = seq_read(global_seqno);
    //将当前线程cbset刷入全局cbset通知waiter干活，并销毁当前线程的记录
    ovsrcu_quiesce_start();
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
        LIST_FOR_EACH (perthread, list_node, &ovsrcu_threads/*ovs所有线程*/) {
            if (perthread->seqno <= target_seqno) {
                ovs_strlcpy_arrays(stalled_thread, perthread->name);
                done = false;
                break;
            }
        }
        ovs_mutex_unlock(&ovsrcu_threads_mutex);

        if (done) {
            break;
        }

        //rcu报警，指明等待线程完成seq变更，但等待超时
        elapsed = time_msec() - start;
        if (elapsed >= warning_threshold) {
            VLOG_WARN("blocked %u ms waiting for %s to quiesce",
                      elapsed, stalled_thread);
            warning_threshold *= 2;
        }

        //设置此线程的建议到期时间为当前时间+warning_threshold
        poll_timer_wait_until(start + warning_threshold);

        //添加seq waiter，如果global_seqno变更再醒过来
        seq_wait(global_seqno, cur_seqno);

        //阻塞等待事件触发
        poll_block();
    }
    ovsrcu_quiesce_end();
}

/* Waits until as many postponed callbacks as possible have executed.
 *
 * As a side effect, stops the background thread that calls the callbacks and
 * prevents it from being restarted.  This means that this function should only
 * be called soon before a process exits, as a mechanism for releasing memory
 * to make memory leaks easier to detect, since any further postponed callbacks
 * won't actually get called.
 *
 * This function can only wait for callbacks registered by the current thread
 * and the background thread that calls the callbacks.  Thus, it will be most
 * effective if other threads have already exited. */
void
ovsrcu_exit(void)
{
    //指明urcu线程退出
    /* Stop the postpone thread and wait for it to exit.  Otherwise, there's no
     * way to wait for that thread to finish calling callbacks itself. */
    if (!single_threaded()) {
        ovsrcu_quiesced();      /* Ensure that the postpone thread exists. */
        latch_set(&postpone_exit);
        ovs_barrier_block(&postpone_barrier);
    }

    /* Repeatedly:
     *
     *    - Wait for a grace period.  One important side effect is to push the
     *      running thread's cbset into 'flushed_cbsets' so that the next call
     *      has something to call.
     *
     *    - Call all the callbacks in 'flushed_cbsets'.  If there aren't any,
     *      we're done, otherwise the callbacks themselves might have requested
     *      more deferred callbacks so we go around again.
     *
     * We limit the number of iterations just in case some bug causes an
     * infinite loop.  This function is just for making memory leaks easier to
     * spot so there's no point in breaking things on that basis. */
    for (int i = 0; i < 8; i++) {
        ovsrcu_synchronize();
        if (!ovsrcu_call_postponed()) {
            break;
        }
    }
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
//为当前进程添加rcu的cbset回调函数及参数
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
        cbset->cbs = xmalloc(MIN_CBS * sizeof *cbset->cbs);
        cbset->n_allocated = MIN_CBS;
        cbset->n_cbs = 0;
    }

    if (cbset->n_cbs == cbset->n_allocated) {
        cbset->cbs = x2nrealloc(cbset->cbs, &cbset->n_allocated,
                                sizeof *cbset->cbs);
    }

    cb = &cbset->cbs[cbset->n_cbs++];
    cb->function = function;
    cb->aux = aux;
}

//等待一个rcu周期，然后执行flushed_cbsets上所有回调集
static bool
ovsrcu_call_postponed(void)
{
    struct ovsrcu_cbset *cbset;
    struct ovs_list cbsets;

    guarded_list_pop_all(&flushed_cbsets, &cbsets);
    if (ovs_list_is_empty(&cbsets)) {
    	//没有rcu回调集，退出
        return false;
    }

    //rcu同步，等待所有线程均过了global_seq变换
    ovsrcu_synchronize();

    //执行cbsets上所有回调集
    LIST_FOR_EACH_POP (cbset, list_node, &cbsets) {
        struct ovsrcu_cb *cb;

        for (cb = cbset->cbs; cb < &cbset->cbs[cbset->n_cbs]; cb++) {
            cb->function(cb->aux);
        }
        free(cbset->cbs);
        free(cbset);
    }

    return true;
}
//线程函数，监控flushed_cbsets_seq,如果其发生变化，则执行flushed_cbsets_seq所有回调
static void *
ovsrcu_postpone_thread(void *arg OVS_UNUSED)
{
    pthread_detach(pthread_self());

    //如果进程没有置退出，则进入
    while (!latch_is_set(&postpone_exit)) {
        uint64_t seqno = seq_read(flushed_cbsets_seq);
        //尝试执行所有flushed_cbsets
        if (!ovsrcu_call_postponed()) {
        	//如果没有cbsets，则等待，直到flushed_cbsets_seq改变
            seq_wait(flushed_cbsets_seq, seqno);
            latch_wait(&postpone_exit);
            poll_block();
        }
    }

    ovs_barrier_block(&postpone_barrier);
    return NULL;
}

//将各线程的cbset提交给全局的flushed_cbsets，唤醒flushed_cbsets_seq上的waiter
static void
ovsrcu_flush_cbset__(struct ovsrcu_perthread *perthread, bool protected)
{
    struct ovsrcu_cbset *cbset = perthread->cbset;

    if (cbset) {
    	//各线程将由mutex保护下，向flushed_cbsets中提交自已的cbset（将各线程的cb提交给全局cbset）
        guarded_list_push_back(&flushed_cbsets, &cbset->list_node, SIZE_MAX);
        perthread->cbset = NULL;

        //变更flushed_cbsets_seq,并唤醒（通知）waiter需要调用的回调已准备好了
        if (protected) {
            //protected为True，则不需要再加锁
            seq_change_protected(flushed_cbsets_seq);
        } else {
            seq_change(flushed_cbsets_seq);
        }
    }
}

//提交线程对应的cb到全局cb,并知会执行回调集合的waiter，使其开始工作
static void
ovsrcu_flush_cbset(struct ovsrcu_perthread *perthread)
{
    ovsrcu_flush_cbset__(perthread, false/*上文已加锁，不需要另外加锁*/);
}

//提交cbset 释放rcu的私有数据
static void
ovsrcu_unregister__(struct ovsrcu_perthread *perthread)
{
    if (perthread->cbset) {
    	//本rcu线程有cbset，提交给全局cb,并通知waiter准备干活。
        ovsrcu_flush_cbset(perthread);
    }

    ovs_mutex_lock(&ovsrcu_threads_mutex);
    ovs_list_remove(&perthread->list_node);
    ovs_mutex_unlock(&ovsrcu_threads_mutex);

    free(perthread);

    //增加全局seq
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

//ovsrcu模块初始化
static void
ovsrcu_init_module(void)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;
    if (ovsthread_once_start(&once)) {
    	//创建rcu需要全局seq
        global_seqno = seq_create();
        //提取rcu回调的perthead_key
        xpthread_key_create(&perthread_key, ovsrcu_thread_exit_cb);
        //线程退出时perthead_key资源清理
        fatal_signal_add_hook(ovsrcu_cancel_thread_exit_cb, NULL, NULL, true);
        ovs_list_init(&ovsrcu_threads);
        ovs_mutex_init(&ovsrcu_threads_mutex);

        guarded_list_init(&flushed_cbsets);
        flushed_cbsets_seq = seq_create();

        ovsthread_once_done(&once);
    }
}

static void
ovsrcu_barrier_func(void *seq_)
{
    struct seq *seq = (struct seq *) seq_;
    seq_change(seq);
}

/* Similar to the kernel rcu_barrier, ovsrcu_barrier waits for all outstanding
 * RCU callbacks to complete. However, unlike the kernel rcu_barrier, which
 * might return immediately if there are no outstanding RCU callbacks,
 * this API will at least wait for a grace period.
 *
 * Another issue the caller might need to know is that the barrier is just
 * for "one-shot", i.e. if inside some RCU callbacks, another RCU callback is
 * registered, this API only guarantees the first round of RCU callbacks have
 * been executed after it returns.
 */
void
ovsrcu_barrier(void)
{
    struct seq *seq = seq_create();
    /* First let all threads flush their cbsets. */
    ovsrcu_synchronize();

    /* Then register a new cbset, ensure this cbset
     * is at the tail of the global list. */
    uint64_t seqno = seq_read(seq);
    ovsrcu_postpone__(ovsrcu_barrier_func, (void *) seq);

    do {
        seq_wait(seq, seqno);
        poll_block();
    } while (seqno == seq_read(seq));

    seq_destroy(seq);
}
