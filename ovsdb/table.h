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

#ifndef OVSDB_TABLE_H
#define OVSDB_TABLE_H 1

#include <stdbool.h>
#include "compiler.h"
#include "openvswitch/hmap.h"
#include "openvswitch/shash.h"

struct json;
struct uuid;
struct ovsdb_txn;

/* Schema for a database table. */
struct ovsdb_table_schema {
    char *name;//表名称
    bool mutable;
    bool is_root;               /* Part of garbage collection root set? */
    unsigned int max_rows;      /* Maximum number of rows. */ //最多多少行
    struct shash columns;       /* Contains "struct ovsdb_column *"s. */ //表包含哪些列
    struct ovsdb_column_set *indexes;//需要几组索引，每组索引索引哪些列
    size_t n_indexes;//几组索引
};

struct ovsdb_table_schema *ovsdb_table_schema_create(
    const char *name, bool mutable, unsigned int max_rows, bool is_root);
struct ovsdb_table_schema *ovsdb_table_schema_clone(
    const struct ovsdb_table_schema *);
void ovsdb_table_schema_destroy(struct ovsdb_table_schema *);

struct ovsdb_error *ovsdb_table_schema_from_json(const struct json *,
                                                 const char *name,
                                                 struct ovsdb_table_schema **)
    OVS_WARN_UNUSED_RESULT;
struct json *ovsdb_table_schema_to_json(const struct ovsdb_table_schema *,
                                        bool default_is_root);

const struct ovsdb_column *ovsdb_table_schema_get_column(
    const struct ovsdb_table_schema *, const char *name);

/* Database table. */

struct ovsdb_table {
    struct ovsdb_table_schema *schema;
    //表事务（用于记录在一个事务中，当前表的变化）
    struct ovsdb_txn_table *txn_table; /* Only if table is in a transaction. */
    //保存每行数据
    struct hmap rows;           /* Contains "struct ovsdb_row"s. */

    /* An array of schema->n_indexes hmaps, each of which contains "struct
     * ovsdb_row"s.  Each of the hmap_nodes in indexes[i] are at index 'i' at
     * the end of struct ovsdb_row, following the 'fields' member. */
    struct hmap *indexes;
};

struct ovsdb_table *ovsdb_table_create(struct ovsdb_table_schema *);
void ovsdb_table_destroy(struct ovsdb_table *);

const struct ovsdb_row *ovsdb_table_get_row(const struct ovsdb_table *,
                                            const struct uuid *);

/* Below functions adds row modification for ovsdb table to the transaction. */
struct ovsdb_error *ovsdb_table_execute_insert(struct ovsdb_txn *txn,
                                               const struct uuid *row_uuid,
                                               struct ovsdb_table *table,
                                               struct json *new);
struct ovsdb_error *ovsdb_table_execute_delete(struct ovsdb_txn *txn,
                                               const struct uuid *row_uuid,
                                               struct ovsdb_table *table);
struct ovsdb_error *ovsdb_table_execute_update(struct ovsdb_txn *txn,
                                               const struct uuid *row_uuid,
                                               struct ovsdb_table *table,
                                               struct json *new, bool xor);

#endif /* ovsdb/table.h */
