/*
 * Copyright (c) 2011, 2012, 2013, 2015, 2016 Nicira, Inc.
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

#ifndef SSET_H
#define SSET_H

#include "openvswitch/hmap.h"
#include "util.h"

#ifdef __cplusplus
extern "C" {
#endif

struct sset_node {
    struct hmap_node hmap_node;
    char name[1];//这个name仅用来说明字符串的起始位置，申请sset_node时，进行了字符串length长度的申请
};

/* A set of strings. */
//提供字符串集合（set数据类型）
struct sset {
    struct hmap map;
};

#define SSET_INITIALIZER(SSET) { HMAP_INITIALIZER(&(SSET)->map) }

/* Basics. */
void sset_init(struct sset *);
void sset_destroy(struct sset *);
void sset_clone(struct sset *, const struct sset *);
void sset_swap(struct sset *, struct sset *);
void sset_moved(struct sset *);

/* String parsing and formatting. */
void sset_from_delimited_string(struct sset *, const char *s,
                                const char *delimiters);
char *sset_join(const struct sset *,
                const char *delimiter, const char *terminator);

/* Count. */
bool sset_is_empty(const struct sset *);
size_t sset_count(const struct sset *);

/* Insertion. */
struct sset_node *sset_add(struct sset *, const char *);
struct sset_node *sset_add_and_free(struct sset *, char *);
void sset_add_assert(struct sset *, const char *);
void sset_add_array(struct sset *, char **, size_t n);

/* Deletion. */
void sset_clear(struct sset *);
void sset_delete(struct sset *, struct sset_node *);
bool sset_find_and_delete(struct sset *, const char *);
void sset_find_and_delete_assert(struct sset *, const char *);
char *sset_pop(struct sset *);

/* Search. */
struct sset_node *sset_find(const struct sset *, const char *);
bool sset_contains(const struct sset *, const char *);
bool sset_equals(const struct sset *, const struct sset *);

struct sset_position {
    struct hmap_position pos;
};

struct sset_node *sset_at_position(const struct sset *,
                                   struct sset_position *);

/* Set operations. */
void sset_intersect(struct sset *, const struct sset *);

/* Iteration macros. */
#define SSET_FOR_EACH(NAME, SSET)               \
    for ((NAME) = SSET_FIRST(SSET);             \
         NAME != NULL;                          \
         (NAME) = SSET_NEXT(SSET, NAME))

#define SSET_FOR_EACH_SAFE_LONG(NAME, NEXT, SSET)   \
    for ((NAME) = SSET_FIRST(SSET);                 \
         (NAME != NULL                              \
          ? (NEXT) = SSET_NEXT(SSET, NAME), true    \
          : false);                                 \
         (NAME) = (NEXT))

#define SSET_FOR_EACH_SAFE_SHORT(NAME, SSET)           \
    for (const char * NAME__next =                     \
         ((NAME) = SSET_FIRST(SSET), NULL);            \
         (NAME != NULL                                 \
          ? (NAME__next = SSET_NEXT(SSET, NAME), true) \
          : (NAME__next = NULL, false));               \
         (NAME) = NAME__next)

#define SSET_FOR_EACH_SAFE(...)                        \
    OVERLOAD_SAFE_MACRO(SSET_FOR_EACH_SAFE_LONG,       \
                        SSET_FOR_EACH_SAFE_SHORT,      \
                        3, __VA_ARGS__)

const char **sset_array(const struct sset *);
const char **sset_sort(const struct sset *);

/* Implementation helper macros. */

#define SSET_NODE_FROM_HMAP_NODE(HMAP_NODE) \
    CONTAINER_OF(HMAP_NODE, struct sset_node, hmap_node)
#define SSET_NAME_FROM_HMAP_NODE(HMAP_NODE) \
    HMAP_NODE == NULL                       \
    ? NULL                                  \
    : (CONST_CAST(const char *, (SSET_NODE_FROM_HMAP_NODE(HMAP_NODE)->name)))
#define SSET_NODE_FROM_NAME(NAME) CONTAINER_OF(NAME, struct sset_node, name)
#define SSET_FIRST(SSET)                                    \
    (BUILD_ASSERT_TYPE(SSET, struct sset *),                \
     SSET_NAME_FROM_HMAP_NODE(hmap_first(&(SSET)->map)))
#define SSET_NEXT(SSET, NAME)                                           \
    (BUILD_ASSERT_TYPE(SSET, struct sset *),                            \
     SSET_NAME_FROM_HMAP_NODE(                                          \
         hmap_next(&(SSET)->map, &SSET_NODE_FROM_NAME(NAME)->hmap_node)))

#ifdef __cplusplus
}
#endif

#endif /* sset.h */
