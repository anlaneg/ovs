/*
 * Copyright (c) 2010, 2011, 2012, 2013, 2015 Nicira, Inc.
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
#include "dummy.h"
#include <string.h>
#include "util.h"

/* Enables support for "dummy" network devices and dpifs, which are useful for
 * testing.  A client program might call this function if it is designed
 * specifically for testing or the user enables it on the command line.
 *
 * 'arg' is parsed to determine the override level (see the definition of enum
 * dummy_level).
 *
 * There is no strong reason why dummy devices shouldn't always be enabled. */
void
dummy_enable(const char *arg)//开始dummy
{
    enum dummy_level level;

    if (!arg || !arg[0]) {//如果未提供参数
        level = DUMMY_OVERRIDE_NONE;
    } else if (!strcmp(arg, "system")) {//提供参数system
        level = DUMMY_OVERRIDE_SYSTEM;
    } else if (!strcmp(arg, "override")) {//提供参数'override'
        level = DUMMY_OVERRIDE_ALL;
    } else {
        ovs_fatal(0, "%s: unknown dummy level", arg);
    }

    netdev_dummy_register(level);//注册netdev dummy
    dpif_dummy_register(level);//注册dpif dummy
    timeval_dummy_register();
    ofpact_dummy_enable();
}

