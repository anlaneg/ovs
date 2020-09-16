/*
 * Copyright (c) 2009, 2010, 2011, 2012, 2013, 2014 Nicira, Inc.
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

#ifndef COVERAGE_H
#define COVERAGE_H 1

/* This file implements a simple form of coverage instrumentation.  Points in
 * source code that are of interest must be explicitly annotated with
 * COVERAGE_INC.  The coverage counters may be logged at any time with
 * coverage_log().
 *
 * This form of coverage instrumentation is intended to be so lightweight that
 * it can be enabled in production builds.  It is obviously not a substitute
 * for traditional coverage instrumentation with e.g. "gcov", but it is still
 * a useful debugging tool. */

#include "ovs-thread.h"
#include "compiler.h"

/* Makes coverage_run run every 5000 ms (5 seconds).
 * If this value is redefined, the new value must
 * divide 60000 (1 minute). */
//每大于此段时间才执行一次coverage_run
#define COVERAGE_RUN_INTERVAL    5000
BUILD_ASSERT_DECL(60000 % COVERAGE_RUN_INTERVAL == 0);

//统计间隔，由于统计时会调用get并在其后会置0，故名clear间隔
#define COVERAGE_CLEAR_INTERVAL  1000
BUILD_ASSERT_DECL(COVERAGE_RUN_INTERVAL % COVERAGE_CLEAR_INTERVAL == 0);

/* Defines the moving average array length. */
//一分钟将运行MIN_AVG_LEN次
#define MIN_AVG_LEN (60000/COVERAGE_RUN_INTERVAL)
#define HR_AVG_LEN  60 //我们最长考虑长度是向前60分钟（即1小时以内）

/* A coverage counter. */
struct coverage_counter {
    const char *const name;            /* Textual name. */ //计数器字符名称
    unsigned int (*const count)(void); /* Gets, zeros this thread's count. */ //计数器get函数（返回计数后，计数将被清0）
    unsigned long long int total;      /* Total count. */ //计算总数
    unsigned long long int last_total;
    /* The moving average arrays. */
    unsigned int min[MIN_AVG_LEN];//在一分钟内每隔5s放一次计数
    unsigned int hr[HR_AVG_LEN];//在一小时内，每隔1分钟放一次计数
};

void coverage_counter_register(struct coverage_counter*);

/* Defines COUNTER.  There must be exactly one such definition at file scope
 * within a program. */
//定义per线程的计数
//xx_count用于返回当前计数，并清0
//xx_add 用于增加计数增量n
// 定义 coverage_counter类型变量 couter_xx
// 定义xx_init_coverage函数（constructor期间调用）,并实现为注册此计数器（见coverage_counter_register）
#define COVERAGE_DEFINE(COUNTER)                                        \
        DEFINE_STATIC_PER_THREAD_DATA(unsigned int,                     \
                                      counter_##COUNTER, 0);            \
        /*获取指定count的计数*/\
        static unsigned int COUNTER##_count(void)                       \
        {                                                               \
            unsigned int *countp = counter_##COUNTER##_get();           \
            unsigned int count = *countp;                               \
            *countp = 0;                                                \
            return count;                                               \
        }                                                               \
        /*增加指定count的计数*/\
        static inline void COUNTER##_add(unsigned int n)                \
        {                                                               \
            *counter_##COUNTER##_get() += n;                            \
        }                                                               \
        extern struct coverage_counter counter_##COUNTER;               \
        struct coverage_counter counter_##COUNTER                       \
            = { #COUNTER, COUNTER##_count, 0, 0, {0}, {0} };            \
            /*完成指定count的名称注册*/\
        OVS_CONSTRUCTOR(COUNTER##_init_coverage) {                      \
            coverage_counter_register(&counter_##COUNTER);              \
        }

/* Adds 1 to COUNTER. */
//增加couter计数
#define COVERAGE_INC(COUNTER) COVERAGE_ADD(COUNTER, 1)

/* Adds AMOUNT to COUNTER. */
#define COVERAGE_ADD(COUNTER, AMOUNT) COUNTER##_add(AMOUNT)

void coverage_init(void);
void coverage_log(void);
void coverage_clear(void);
void coverage_try_clear(void);
void coverage_run(void);

#endif /* coverage.h */
