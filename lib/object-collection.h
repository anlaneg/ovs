/*
 * Copyright (c) 2016 Nicira, Inc.
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

#ifndef OBJECT_COLLECTION_H
#define OBJECT_COLLECTION_H 1

#include <limits.h>
#include <stdlib.h>

/* A set of object pointers. */
/*提供一组对象的指针*/
struct object_collection {
    void **objs;                /* Objects. */
    /*实际在objs中存放的obj数目*/
    size_t n;                   /* Number of objects collected. */
    /*当前可在objs中存放的obj最大数*/
    size_t capacity;            /* Number of objects that fit in 'objs'. */
    /*首次准备的obj容间，避免首次申请*/
    void *stub[5];              /* Preallocated array to avoid malloc(). */
};

//初始化，采用stub做为起始大小
void object_collection_init(struct object_collection *);
void object_collection_add(struct object_collection *, void *);
void object_collection_remove(struct object_collection *, void *);
void object_collection_move(struct object_collection *to,
                            struct object_collection *from);
void *object_collection_detach(struct object_collection *);
void object_collection_destroy(struct object_collection *);

/* Macro for declaring type-safe pointer collections.  'TYPE' is the pointer
 * type which are collected, 'NAME' is the name for the type to be used in the
 * function names. */
//object_collection通过指针来存放obj,其为void*类型，这一组help函数，用于帮助类型type
//来存储限制类型的obj

#define DECL_OBJECT_COLLECTION(TYPE, NAME)                              \
struct NAME##_collection {                                              \
    struct object_collection collection;                                \
};                                                                      \
                                                                        \
/*集合初始化*/\
static inline void NAME##_collection_init(struct NAME##_collection *coll) \
{                                                                       \
    object_collection_init(&coll->collection);                          \
}                                                                       \
                                                                        \
/*向集合中添加元素*/\
static inline void NAME##_collection_add(struct NAME##_collection *coll, \
                                         TYPE obj)                      \
{                                                                       \
    object_collection_add(&coll->collection, obj);                      \
}                                                                       \
                                                                        \
/*移除集合中的元素*/\
static inline void NAME##_collection_remove(struct NAME##_collection *coll, \
                                            TYPE obj)                   \
{                                                                       \
    object_collection_remove(&coll->collection, obj);                   \
}                                                                       \
                                                                        \
/*将集合from中的元素，移存到to中*/\
static inline void NAME##_collection_move(struct NAME##_collection *to, \
                                          struct NAME##_collection *from) \
{                                                                       \
    object_collection_move(&to->collection, &from->collection);         \
}                                                                       \
                                                                        \
/*销毁集合coll*/\
static inline void NAME##_collection_destroy(struct NAME##_collection *coll) \
{                                                                       \
    object_collection_destroy(&coll->collection);                       \
}                                                                       \
                                                                        \
/*返回集合coll中的元素指针*/\
static inline TYPE* NAME##_collection_##NAME##s(const struct NAME##_collection *coll) \
{                                                                       \
    return (TYPE*)coll->collection.objs;                                \
}                                                                       \
                                                                        \
/*返回集合coll中元素的数目*/\
static inline size_t NAME##_collection_n(const struct NAME##_collection *coll) \
{                                                                       \
    return coll->collection.n;                                          \
}                                                                       \
                                                                        \
/*返回集合中coll中的元素数组*/\
static inline TYPE* NAME##_collection_detach(struct NAME##_collection *coll) \
{                                                                       \
    return (TYPE*)object_collection_detach(&coll->collection);          \
}

#endif /* object-collection.h */
