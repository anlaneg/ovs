/*
 * Copyright (c) 2013, 2014 Nicira, Inc.
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

#include "seq.h"

#include <stdbool.h>

#include "coverage.h"
#include "hash.h"
#include "openvswitch/hmap.h"
#include "latch.h"
#include "openvswitch/list.h"
#include "ovs-thread.h"
#include "openvswitch/poll-loop.h"

COVERAGE_DEFINE(seq_change);

/* A sequence number object. */
struct seq {
    //seq序列
    uint64_t value OVS_GUARDED;
    //seq的等待队列
    struct hmap waiters OVS_GUARDED; /* Contains 'struct seq_waiter's. */
};

/* A thread waiting on a particular seq. */
struct seq_waiter {
    struct hmap_node hmap_node OVS_GUARDED; /* In 'seq->waiters'. *///从属于哪个seq
    struct seq *seq OVS_GUARDED;            /* Seq being waited for. *///加入到从属的seq对应的waiters哈希表时使用
    unsigned int ovsthread_id OVS_GUARDED;  /* Key in 'waiters' hmap. *///从属于哪个线程（ovs对线程的编号）

    struct seq_thread *thread OVS_GUARDED;  /* Thread preparing to wait. */
    struct ovs_list list_node OVS_GUARDED;  /* In 'thread->waiters'. */ //waiter本身由链串起来

    uint64_t value OVS_GUARDED; /* seq->value we're waiting to change. */
};

/* A thread that might be waiting on one or more seqs. */
struct seq_thread {
    struct ovs_list waiters OVS_GUARDED; /* Contains 'struct seq_waiter's. */
    struct latch latch OVS_GUARDED;  /* Wakeup latch for this thread. */
    bool waiting OVS_GUARDED;        /* True if latch_wait() already called. */
};

//所有seq共有这一把锁
static struct ovs_mutex seq_mutex = OVS_MUTEX_INITIALIZER;

static uint64_t seq_next OVS_GUARDED_BY(seq_mutex) = 1;//用于产生序列

static pthread_key_t seq_thread_key;/*seq线程对应的key*/

static void seq_init(void);
static struct seq_thread *seq_thread_get(void) OVS_REQUIRES(seq_mutex);
static void seq_thread_exit(void *thread_) OVS_EXCLUDED(seq_mutex);
static void seq_thread_woke(struct seq_thread *) OVS_REQUIRES(seq_mutex);
static void seq_waiter_destroy(struct seq_waiter *) OVS_REQUIRES(seq_mutex);
static void seq_wake_waiters(struct seq *) OVS_REQUIRES(seq_mutex);

/* Creates and returns a new 'seq' object. */
//创建一个seq对象
struct seq * OVS_EXCLUDED(seq_mutex)
seq_create(void)
{
    struct seq *seq;

    seq_init();

    //创建一个seq
    seq = xmalloc(sizeof *seq);

    COVERAGE_INC(seq_change);

    ovs_mutex_lock(&seq_mutex);
    //加锁，产生seq_next,给seq赋初始值
    seq->value = seq_next++;
    //初始化seq对应的等待队列
    hmap_init(&seq->waiters);
    ovs_mutex_unlock(&seq_mutex);

    return seq;//返回对应的seq
}

/* Destroys 'seq', waking up threads that were waiting on it, if any. */
void
seq_destroy(struct seq *seq)//seq销毁时，需要销毁waiters上对应的元素
     OVS_EXCLUDED(seq_mutex)
{
    ovs_mutex_lock(&seq_mutex);
    seq_wake_waiters(seq);
    hmap_destroy(&seq->waiters);
    free(seq);
    ovs_mutex_unlock(&seq_mutex);
}

int
seq_try_lock(void)
{
    return ovs_mutex_trylock(&seq_mutex);
}

void
seq_lock(void)
    OVS_ACQUIRES(seq_mutex)
{
    ovs_mutex_lock(&seq_mutex);
}

void
seq_unlock(void)
    OVS_RELEASES(seq_mutex)
{
    ovs_mutex_unlock(&seq_mutex);
}

/* Increments 'seq''s sequence number, waking up any threads that are waiting
 * on 'seq'. */
void
seq_change_protected(struct seq *seq)
    OVS_REQUIRES(seq_mutex)
{
    COVERAGE_INC(seq_change);

    seq->value = seq_next++;//变更序列，并唤醒waiter
    seq_wake_waiters(seq);
}

/* Increments 'seq''s sequence number, waking up any threads that are waiting
 * on 'seq'. */
//变更seq序列，唤醒在此seq上等待基变换的所有waiter
void
seq_change(struct seq *seq)
    OVS_EXCLUDED(seq_mutex)
{
    ovs_mutex_lock(&seq_mutex);
    seq_change_protected(seq);
    ovs_mutex_unlock(&seq_mutex);
}

/* Returns 'seq''s current sequence number (which could change immediately).
 *
 * seq_read() and seq_wait() can be used together to yield a race-free wakeup
 * when an object changes, even without an ability to lock the object.  See
 * Usage in seq.h for details. */
uint64_t
seq_read_protected(const struct seq *seq)//返回序列号
    OVS_REQUIRES(seq_mutex)
{
    return seq->value;
}

/* Returns 'seq''s current sequence number (which could change immediately).
 *
 * seq_read() and seq_wait() can be used together to yield a race-free wakeup
 * when an object changes, even without an ability to lock the object.  See
 * Usage in seq.h for details. */
//返回序列对应的值
uint64_t
seq_read(const struct seq *seq)
    OVS_EXCLUDED(seq_mutex)
{
    uint64_t value;

    ovs_mutex_lock(&seq_mutex);
    value = seq_read_protected(seq);
    ovs_mutex_unlock(&seq_mutex);

    return value;
}

static void
seq_wait__(struct seq *seq, uint64_t value, const char *where)
    OVS_REQUIRES(seq_mutex)
{
    unsigned int id = ovsthread_id_self();
    uint32_t hash = hash_int(id, 0);
    struct seq_waiter *waiter;

    //如果seq->waiters上有waiter,则检查是否有等待此seq的waiter,如果有，则不加入
    //如果无，且waiter值与当前value不一致，则顺手wakeup这个waiter
    HMAP_FOR_EACH_IN_BUCKET (waiter, hmap_node, hash, &seq->waiters) {
        if (waiter->ovsthread_id == id) {//已存在情况
            if (waiter->value != value) {
            	//立即唤醒
                /* The current value is different from the value we've already
                 * waited for, */
                poll_immediate_wake_at(where);
            } else {
                /* Already waiting on 'value', nothing more to do. */
            }
            return;
        }
    }

    //waiter不存在，则创建
    waiter = xmalloc(sizeof *waiter);
    waiter->seq = seq;
    hmap_insert(&seq->waiters, &waiter->hmap_node, hash);
    waiter->ovsthread_id = id;
    waiter->value = value;
    waiter->thread = seq_thread_get();
    ovs_list_push_back(&waiter->thread->waiters, &waiter->list_node);

    if (!waiter->thread->waiting) {
        latch_wait_at(&waiter->thread->latch, where);
        waiter->thread->waiting = true;
    }
}

/* Causes the following poll_block() to wake up when 'seq''s sequence number
 * changes from 'value'.  (If 'seq''s sequence number isn't 'value', then
 * poll_block() won't block at all.)
 *
 * seq_read() and seq_wait() can be used together to yield a race-free wakeup
 * when an object changes, even without an ability to lock the object.  See
 * Usage in seq.h for details.
 *
 * ('where' is used in debug logging.  Commonly one would use seq_wait() to
 * automatically provide the caller's source file and line number for
 * 'where'.) */
//尝试着去创建等待句柄，如果已变化，则立即唤醒
void
seq_wait_at(const struct seq *seq_, uint64_t value, const char *where)
    OVS_EXCLUDED(seq_mutex)
{
    struct seq *seq = CONST_CAST(struct seq *, seq_);

    ovs_mutex_lock(&seq_mutex);//加锁后再检查
    if (value == seq->value) {
    	//seq仍然为value,未发生变更，注册seq等待句柄
        seq_wait__(seq, value, where);
    } else {
    	//seq已变更，立即唤醒
        poll_immediate_wake_at(where);
    }
    ovs_mutex_unlock(&seq_mutex);
}

/* Called by poll_block() just before it returns, this function destroys any
 * seq_waiter objects associated with the current thread. */
void
seq_woke(void)
    OVS_EXCLUDED(seq_mutex)
{
    struct seq_thread *thread;

    seq_init();

    thread = pthread_getspecific(seq_thread_key);
    if (thread) {
        ovs_mutex_lock(&seq_mutex);
        seq_thread_woke(thread);
        thread->waiting = false;
        ovs_mutex_unlock(&seq_mutex);
    }
}

static void
seq_init(void)//每线程执行一次
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;

    if (ovsthread_once_start(&once)) {
        xpthread_key_create(&seq_thread_key, seq_thread_exit);
        ovsthread_once_done(&once);
    }
}

static struct seq_thread *
seq_thread_get(void)//构造每个线程对应的seq_thread
    OVS_REQUIRES(seq_mutex)
{
    struct seq_thread *thread = pthread_getspecific(seq_thread_key);
    if (!thread) {
        thread = xmalloc(sizeof *thread);
        ovs_list_init(&thread->waiters);
        latch_init(&thread->latch);
        thread->waiting = false;

        xpthread_setspecific(seq_thread_key, thread);
    }
    return thread;
}

static void
seq_thread_exit(void *thread_)//销毁每个线程自已对应的seq_thread
    OVS_EXCLUDED(seq_mutex)
{
    struct seq_thread *thread = thread_;

    ovs_mutex_lock(&seq_mutex);
    seq_thread_woke(thread);
    latch_destroy(&thread->latch);
    free(thread);
    ovs_mutex_unlock(&seq_mutex);
}

static void
seq_thread_woke(struct seq_thread *thread)//唤醒waiter
    OVS_REQUIRES(seq_mutex)
{
    struct seq_waiter *waiter;

    LIST_FOR_EACH_SAFE (waiter, list_node, &thread->waiters) {
        ovs_assert(waiter->thread == thread);
        seq_waiter_destroy(waiter);
    }
    latch_poll(&thread->latch);
}

static void
seq_waiter_destroy(struct seq_waiter *waiter)
    OVS_REQUIRES(seq_mutex)
{
    hmap_remove(&waiter->seq->waiters, &waiter->hmap_node);
    ovs_list_remove(&waiter->list_node);
    free(waiter);
}

static void
seq_wake_waiters(struct seq *seq)
    OVS_REQUIRES(seq_mutex)
{
    struct seq_waiter *waiter;

    HMAP_FOR_EACH_SAFE (waiter, hmap_node, &seq->waiters) {//遍历waiter
        latch_set(&waiter->thread->latch);
        seq_waiter_destroy(waiter);
    }
}
