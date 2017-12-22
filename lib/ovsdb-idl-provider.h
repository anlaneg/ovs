/* Copyright (c) 2009, 2010, 2011, 2012, 2016 Nicira, Inc.
 * Copyright (C) 2016 Hewlett Packard Enterprise Development LP
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

#ifndef OVSDB_IDL_PROVIDER_H
#define OVSDB_IDL_PROVIDER_H 1

#include "openvswitch/hmap.h"
#include "openvswitch/list.h"
#include "ovsdb-idl.h"
#include "ovsdb-map-op.h"
#include "ovsdb-set-op.h"
#include "ovsdb-types.h"
#include "openvswitch/shash.h"
#include "uuid.h"

#ifdef __cplusplus
extern "C" {
#endif

/* A local copy of a row in an OVSDB table, replicated from an OVSDB server.
 * This structure is used as a header for a larger structure that translates
 * the "struct ovsdb_datum"s into easier-to-use forms, via the ->parse() and
 * ->unparse functions in struct ovsdb_idl_column.  (Those functions are
 * generated automatically via ovsdb-idlc.)
 *
 * When no transaction is in progress:
 *
 *     - 'old_datum' points to the data committed to the database and currently
 *       in the row.
 *
 *     - 'new_datum == old_datum'.
 *
 * When a transaction is in progress, the situation is a little different.  For
 * a row inserted in the transaction, 'old_datum' is NULL and 'new_datum'
 * points to the row's initial contents.  Otherwise:
 *
 *     - 'old_datum' points to the data committed to the database and currently
 *       in the row.  (This is the same as when no transaction is in progress.)
 *
 *     - If the transaction does not modify the row, 'new_datum == old_datum'.
 *
 *     - If the transaction modifies the row, 'new_datum' points to the
 *       modified data.
 *
 *     - If the transaction deletes the row, 'new_datum' is NULL.
 *
 * Thus:
 *
 *     - 'old_datum' always points to committed data, except that it is NULL if
 *       the row is inserted within the current transaction.
 *
 *     - 'new_datum' always points to the newest, possibly uncommitted version
 *       of the row's data, except that it is NULL if the row is deleted within
 *       the current transaction.
 */
struct ovsdb_idl_row {
    struct hmap_node hmap_node; /* In struct ovsdb_idl_table's 'rows'. */
    struct uuid uuid;           /* Row "_uuid" field. */ //行对应的uuid
    struct ovs_list src_arcs;   /* Forward arcs (ovsdb_idl_arc.src_node). */
    struct ovs_list dst_arcs;   /* Backward arcs (ovsdb_idl_arc.dst_node). */
    struct ovsdb_idl_table *table; /* Containing table. *///属于哪张表
    //当新插入时，old,new指向同一块数据，更新时，new指向新的数据,old指向原来的数据，删除时new指向null，old指向原来的数据
    struct ovsdb_datum *old_datum; /* Committed data (null if orphaned). */

    /* Transactional data. *///更新或者新插入行时，此字符不为null
    struct ovsdb_datum *new_datum; /* Modified data (null to delete row). */
    unsigned long int *prereqs; /* Bitmap of "old_datum" columns to verify. *///每个列一个bit位
    unsigned long int *written; /* Bitmap of "new_datum" columns to write. *///标记行哪些字段被更新了
    struct hmap_node txn_node;  /* Node in ovsdb_idl_txn's list. */
    unsigned long int *map_op_written; /* Bitmap of columns pending map ops. */
    struct map_op_list **map_op_lists; /* Per-column map operations. */
    unsigned long int *set_op_written; /* Bitmap of columns pending set ops. */
    struct set_op_list **set_op_lists; /* Per-column set operations. */

    /* Tracking data */
    unsigned int change_seqno[OVSDB_IDL_CHANGE_MAX];
    struct ovs_list track_node; /* Rows modified/added/deleted by IDL */
    unsigned long int *updated; /* Bitmap of columns updated by IDL */
};

struct ovsdb_idl_column {
    char *name;//列名称
    struct ovsdb_type type;//列类型
    bool is_mutable;
    void (*parse)(struct ovsdb_idl_row *, const struct ovsdb_datum *);//解析并填充row
    void (*unparse)(struct ovsdb_idl_row *);//反解析，释放解析占用的资源
};

//idl = Interface Definition Language
struct ovsdb_idl_table_class {
    char *name;//表名称
    bool is_root;//是否为根表
    bool is_singleton;
    const struct ovsdb_idl_column *columns;//列信息
    size_t n_columns;//有多少列
    size_t allocation_size;//申请多大空间（生成的代码中第一个字段为ovsdb_idl_row
    void (*row_init)(struct ovsdb_idl_row *);//行初始化
};

struct ovsdb_idl_table {
    const struct ovsdb_idl_table_class *class_;//table类型
    unsigned char *modes;    /* OVSDB_IDL_* bitmasks, indexed by column. *///表模式
    bool need_table;         /* Monitor table even if no columns are selected
                              * for replication. */
    struct shash columns;    /* Contains "const struct ovsdb_idl_column *"s. */ //按列名称索引列struct ovsdb_idl_column
    struct hmap rows;        /* Contains "struct ovsdb_idl_row"s. */ //数据行hashtable（osdb_idl_row结构）
    struct ovsdb_idl *idl;   /* Containing idl. */
    unsigned int change_seqno[OVSDB_IDL_CHANGE_MAX];
    struct shash indexes;    /* Contains "struct ovsdb_idl_index"s */
    struct ovs_list track_list; /* Tracked rows (ovsdb_idl_row.track_node). */
    //monitor条件
    struct ovsdb_idl_condition condition;
    //monitor条件有变更
    bool cond_changed;
};

struct ovsdb_idl_class {
    const char *database;       /* <db-name> for this database. */ //库名称
    const struct ovsdb_idl_table_class *tables;//表元数据数组
    size_t n_tables;//表数目
};

/*
 * Structure containing the per-column configuration of the index.
 */
struct ovsdb_idl_index_column {
    const struct ovsdb_idl_column *column; /* Column used for index key. */
    column_comparator *comparer; /* Column comparison function. */
    int sorting_order; /* Sorting order (ascending or descending). */
};

/*
 * Defines a IDL compound index
 */
struct ovsdb_idl_index {
    struct skiplist *skiplist;    /* Skiplist with pointers to rows. */
    struct ovsdb_idl_index_column *columns; /* Columns configuration */
    size_t n_columns;             /* Number of columns in index. */
    size_t alloc_columns;         /* Size allocated memory for columns,
                                     comparers and sorting order. */
    bool ins_del;                 /* True if a row in the index is being
                                     inserted or deleted; if true, the
                                     search key is augmented with the
                                     UUID and address in order to discriminate
                                     between entries with identical keys. */
    const struct ovsdb_idl_table *table; /* Table that owns this index */
    const char *index_name;       /* The name of this index. */
};

struct ovsdb_idl_row *ovsdb_idl_get_row_arc(
    struct ovsdb_idl_row *src,
    const struct ovsdb_idl_table_class *dst_table,
    const struct uuid *dst_uuid);

void ovsdb_idl_txn_verify(const struct ovsdb_idl_row *,
                          const struct ovsdb_idl_column *);

struct ovsdb_idl_txn *ovsdb_idl_txn_get(const struct ovsdb_idl_row *);

#ifdef __cplusplus
}
#endif

#endif /* ovsdb-idl-provider.h */
