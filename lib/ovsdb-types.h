/* Copyright (c) 2009, 2010, 2011 Nicira, Inc.
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

#ifndef OVSDB_TYPES_H
#define OVSDB_TYPES_H 1

#include <float.h>
#include <stdbool.h>
#include <stdint.h>
#include "compiler.h"
#include "uuid.h"

#ifdef __cplusplus
extern "C" {
#endif

struct json;

/* An atomic type: one that OVSDB regards as a single unit of data. */
enum ovsdb_atomic_type {
    OVSDB_TYPE_VOID,            /* No value. */ //空类型
    OVSDB_TYPE_INTEGER,         /* Signed 64-bit integer. */ //有符号整型
    OVSDB_TYPE_REAL,            /* IEEE 754 double-precision floating point. */ //浮点型
    OVSDB_TYPE_BOOLEAN,         /* True or false. */ //布尔型
    OVSDB_TYPE_STRING,          /* UTF-8 string. */ //字符串类型
    OVSDB_TYPE_UUID,            /* RFC 4122 UUID referencing a table row. */ //uuid类型
    OVSDB_N_TYPES
};

static inline bool ovsdb_atomic_type_is_valid(enum ovsdb_atomic_type);
bool ovsdb_atomic_type_from_string(const char *, enum ovsdb_atomic_type *);
struct ovsdb_error *ovsdb_atomic_type_from_json(enum ovsdb_atomic_type *,
                                                const struct json *);
const char *ovsdb_atomic_type_to_string(enum ovsdb_atomic_type);
struct json *ovsdb_atomic_type_to_json(enum ovsdb_atomic_type);

/* An atomic type plus optional constraints. */

enum ovsdb_ref_type {
    OVSDB_REF_STRONG,           /* Target must exist. */
    OVSDB_REF_WEAK              /* Delete reference if target disappears. */
};

struct ovsdb_integer_constraints {
    int64_t min;        /* minInteger or INT64_MIN. */
    int64_t max;        /* maxInteger or INT64_MAX. */
};

struct ovsdb_real_constraints {
    double min;         /* minReal or -DBL_MAX. */
    double max;         /* minReal or DBL_MAX. */
};

struct ovsdb_string_constraints {
    unsigned int minLen; /* minLength or 0. */
    unsigned int maxLen; /* maxLength or UINT_MAX. */
};

struct ovsdb_uuid_constraints {
    char *refTableName; /* Name of referenced table, or NULL. */
    struct ovsdb_table *refTable; /* Referenced table, if available. */
    enum ovsdb_ref_type refType;  /* Reference type. */
};

//标记类型，并指明各类型的取值范围
struct ovsdb_base_type {
    enum ovsdb_atomic_type type;//类型（按此type可提供约束信息）

    /* If nonnull, a datum with keys of type 'type' that expresses all the
     * valid values for this base_type. */
    struct ovsdb_datum *enum_;//枚举类型

    //约束信息
    union {
        struct ovsdb_integer_constraints integer;//OVSDB_TYPE_INTEGER类型
        struct ovsdb_real_constraints real;//OVSDB_TYPE_REAL类型
        /* No constraints for Boolean types. */
        struct ovsdb_string_constraints string;//OVSDB_TYPE_STRING类型
        struct ovsdb_uuid_constraints uuid;//OVSDB_TYPE_UUID类型
    };
};

#define OVSDB_BASE_VOID_INIT    { .type = OVSDB_TYPE_VOID }
#define OVSDB_BASE_INTEGER_INIT { .type = OVSDB_TYPE_INTEGER,           \
                                  .integer = { INT64_MIN, INT64_MAX } }
#define OVSDB_BASE_REAL_INIT    { .type = OVSDB_TYPE_REAL,          \
                                  .real = { -DBL_MAX, DBL_MAX } }
#define OVSDB_BASE_BOOLEAN_INIT { .type = OVSDB_TYPE_BOOLEAN }
#define OVSDB_BASE_STRING_INIT  { .type = OVSDB_TYPE_STRING,    \
                                  .string = { 0, UINT_MAX } }
#define OVSDB_BASE_UUID_INIT    { .type = OVSDB_TYPE_UUID,      \
                                  .uuid = { NULL, NULL, 0 } }

void ovsdb_base_type_init(struct ovsdb_base_type *, enum ovsdb_atomic_type);
void ovsdb_base_type_clone(struct ovsdb_base_type *,
                           const struct ovsdb_base_type *);
void ovsdb_base_type_destroy(struct ovsdb_base_type *);

bool ovsdb_base_type_is_valid(const struct ovsdb_base_type *);
bool ovsdb_base_type_has_constraints(const struct ovsdb_base_type *);
void ovsdb_base_type_clear_constraints(struct ovsdb_base_type *);
const struct ovsdb_type *ovsdb_base_type_get_enum_type(enum ovsdb_atomic_type);

struct ovsdb_error *ovsdb_base_type_from_json(struct ovsdb_base_type *,
                                              const struct json *)
    OVS_WARN_UNUSED_RESULT;
struct json *ovsdb_base_type_to_json(const struct ovsdb_base_type *);

static inline bool ovsdb_base_type_is_ref(const struct ovsdb_base_type *);
static inline bool ovsdb_base_type_is_strong_ref(
    const struct ovsdb_base_type *);
static inline bool ovsdb_base_type_is_weak_ref(const struct ovsdb_base_type *);

/* An OVSDB type.
 *
 * Several rules constrain the valid types.  See ovsdb_type_is_valid() (in
 * ovsdb-types.c) for details.
 *
 * If 'value_type' is OVSDB_TYPE_VOID, 'n_min' is 1, and 'n_max' is 1, then the
 * type is a single atomic 'key_type'.
 *
 * 当value字段的类型是OVSDB_TYPE_VOID时，如果n_min与n_max同为1，则这此类型是一个单值类型
 * 它的类型由key指定
 *
 * If 'value_type' is OVSDB_TYPE_VOID and 'n_min' or 'n_max' (or both) has a
 * value other than 1, then the type is a set of 'key_type'.  If 'n_min' is 0
 * and 'n_max' is 1, then the type can also be considered an optional
 * 'key_type'.
 *
 * 当value字段是OVSDB_TYPE_VOID时，如果n_min或者n_max（或者它们俩）大于1，那么这个类型是一个key类型的
 * 集合类型（或者认为是数组），当n_min为0，n_max为1，则此类型可以按可选对待
 *
 * If 'value_type' is not OVSDB_TYPE_VOID, then the type is a map from
 * 'key_type' to 'value_type'.  If 'n_min' is 0 and 'n_max' is 1, then the type
 * can also be considered an optional pair of 'key_type' and 'value_type'.
 *
 * 当value字段不是OVSDB_TYPE_VOID,那么这个类型是一个map,提供自key类型到value类型的映射。
 * 如果n_min是0并且n_max是1，由此类型型是一个可选键值对。
 */
struct ovsdb_type {
	//支持map方式，故存在key,value
    struct ovsdb_base_type key;
    struct ovsdb_base_type value;//如果没有value,则value取值为OVSDB_TYPE_VOID
    //min,max合起来表示，‘单个’，“可选“，‘多个，且最多容许多少个，至少有多少个',
    unsigned int n_min;
    unsigned int n_max;         /* UINT_MAX stands in for "unlimited". */
};

#define OVSDB_TYPE_SCALAR_INITIALIZER(KEY) { KEY, OVSDB_BASE_VOID_INIT, 1, 1 }

extern const struct ovsdb_type ovsdb_type_integer;
extern const struct ovsdb_type ovsdb_type_real;
extern const struct ovsdb_type ovsdb_type_boolean;
extern const struct ovsdb_type ovsdb_type_string;
extern const struct ovsdb_type ovsdb_type_uuid;

void ovsdb_type_clone(struct ovsdb_type *, const struct ovsdb_type *);
void ovsdb_type_destroy(struct ovsdb_type *);

bool ovsdb_type_is_valid(const struct ovsdb_type *);

static inline bool ovsdb_type_is_scalar(const struct ovsdb_type *);
static inline bool ovsdb_type_is_optional(const struct ovsdb_type *);
static inline bool ovsdb_type_is_optional_scalar(
    const struct ovsdb_type *);
static inline bool ovsdb_type_is_composite(const struct ovsdb_type *);
static inline bool ovsdb_type_is_set(const struct ovsdb_type *);
static inline bool ovsdb_type_is_map(const struct ovsdb_type *);

char *ovsdb_type_to_english(const struct ovsdb_type *);

struct ovsdb_error *ovsdb_type_from_json(struct ovsdb_type *,
                                         const struct json *)
    OVS_WARN_UNUSED_RESULT;
struct json *ovsdb_type_to_json(const struct ovsdb_type *);

/* Inline function implementations. */

static inline bool
ovsdb_atomic_type_is_valid(enum ovsdb_atomic_type atomic_type)
{
    return (int) atomic_type >= 0 && atomic_type < OVSDB_N_TYPES;
}

//是否有引用
static inline bool
ovsdb_base_type_is_ref(const struct ovsdb_base_type *base)
{
    return base->type == OVSDB_TYPE_UUID && base->uuid.refTableName;
}

//是否为强引用
static inline bool
ovsdb_base_type_is_strong_ref(const struct ovsdb_base_type *base)
{
    return (ovsdb_base_type_is_ref(base)
            && base->uuid.refType == OVSDB_REF_STRONG);
}

static inline bool
ovsdb_base_type_is_weak_ref(const struct ovsdb_base_type *base)
{
    return (ovsdb_base_type_is_ref(base)
            && base->uuid.refType == OVSDB_REF_WEAK);
}

//检查类型是否为标量，标量的定义：仅单个值，type->value为空
static inline bool ovsdb_type_is_scalar(const struct ovsdb_type *type)
{
    return (type->value.type == OVSDB_TYPE_VOID
            && type->n_min == 1 && type->n_max == 1);
}

//此类型可以不赋值
static inline bool ovsdb_type_is_optional(const struct ovsdb_type *type)
{
    return type->n_min == 0;
}

//检查类型是否为可选的标量（即容许０或１个值）
static inline bool ovsdb_type_is_optional_scalar(
    const struct ovsdb_type *type)
{
    return (type->value.type == OVSDB_TYPE_VOID
            && type->n_min == 0 && type->n_max == 1);
}

//容许有多个
static inline bool ovsdb_type_is_composite(const struct ovsdb_type *type)
{
    return type->n_max > 1;
}

//集合（容许有０到多个值）
static inline bool ovsdb_type_is_set(const struct ovsdb_type *type)
{
    return (type->value.type == OVSDB_TYPE_VOID
            && (type->n_min != 1 || type->n_max != 1));
}

//map类型
static inline bool ovsdb_type_is_map(const struct ovsdb_type *type)
{
    return type->value.type != OVSDB_TYPE_VOID;
}

#ifdef __cplusplus
}
#endif

#endif /* ovsdb-types.h */
