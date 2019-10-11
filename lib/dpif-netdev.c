/*
 * Copyright (c) 2009-2014, 2016-2018 Nicira, Inc.
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
#include "dpif-netdev.h"
#include "dpif-netdev-private.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <net/if.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "bitmap.h"
#include "cmap.h"
#include "conntrack.h"
#include "coverage.h"
#include "ct-dpif.h"
#include "csum.h"
#include "dp-packet.h"
#include "dpif.h"
#include "dpif-netdev-perf.h"
#include "dpif-provider.h"
#include "dummy.h"
#include "fat-rwlock.h"
#include "flow.h"
#include "hmapx.h"
#include "id-pool.h"
#include "ipf.h"
#include "netdev.h"
#include "netdev-offload.h"
#include "netdev-provider.h"
#include "netdev-vport.h"
#include "netlink.h"
#include "odp-execute.h"
#include "odp-util.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/list.h"
#include "openvswitch/match.h"
#include "openvswitch/ofp-parse.h"
#include "openvswitch/ofp-print.h"
#include "openvswitch/ofpbuf.h"
#include "openvswitch/shash.h"
#include "openvswitch/vlog.h"
#include "ovs-numa.h"
#include "ovs-rcu.h"
#include "packets.h"
#include "openvswitch/poll-loop.h"
#include "pvector.h"
#include "random.h"
#include "seq.h"
#include "smap.h"
#include "sset.h"
#include "timeval.h"
#include "tnl-neigh-cache.h"
#include "tnl-ports.h"
#include "unixctl.h"
#include "util.h"
#include "uuid.h"

VLOG_DEFINE_THIS_MODULE(dpif_netdev);

/* Auto Load Balancing Defaults */
#define ALB_ACCEPTABLE_IMPROVEMENT       25
#define ALB_PMD_LOAD_THRESHOLD           95
#define ALB_PMD_REBALANCE_POLL_INTERVAL  1 /* 1 Min */
#define MIN_TO_MSEC                  60000

#define FLOW_DUMP_MAX_BATCH 50
/* Use per thread recirc_depth to prevent recirculation loop. */
#define MAX_RECIRC_DEPTH 6
DEFINE_STATIC_PER_THREAD_DATA(uint32_t, recirc_depth, 0)

/* Use instant packet send by default. */
#define DEFAULT_TX_FLUSH_INTERVAL 0

/* Configuration parameters. */
enum { MAX_FLOWS = 65536 };     /* Maximum number of flows in flow table. */
enum { MAX_METERS = 65536 };    /* Maximum number of meters. */
enum { MAX_BANDS = 8 };         /* Maximum number of bands / meter. */
enum { N_METER_LOCKS = 64 };    /* Maximum number of meters. */

/* Protects against changes to 'dp_netdevs'. */
static struct ovs_mutex dp_netdev_mutex = OVS_MUTEX_INITIALIZER;

/* Contains all 'struct dp_netdev's. */
//系统所有由netdev创建的datapath
static struct shash dp_netdevs OVS_GUARDED_BY(dp_netdev_mutex)
    = SHASH_INITIALIZER(&dp_netdevs);

static struct vlog_rate_limit upcall_rl = VLOG_RATE_LIMIT_INIT(600, 600);

//支持的状态
#define DP_NETDEV_CS_SUPPORTED_MASK (CS_NEW | CS_ESTABLISHED | CS_RELATED \
                                     | CS_INVALID | CS_REPLY_DIR | CS_TRACKED \
                                     | CS_SRC_NAT | CS_DST_NAT)
#define DP_NETDEV_CS_UNSUPPORTED_MASK (~(uint32_t)DP_NETDEV_CS_SUPPORTED_MASK)

static struct odp_support dp_netdev_support = {
    .max_vlan_headers = SIZE_MAX,
    .max_mpls_depth = SIZE_MAX,
    .recirc = true,
    .ct_state = true,
    .ct_zone = true,
    .ct_mark = true,
    .ct_label = true,
    .ct_state_nat = true,
    .ct_orig_tuple = true,
    .ct_orig_tuple6 = true,
};

/* EMC cache and SMC cache compose the datapath flow cache (DFC)
 *
 * Exact match cache for frequently used flows
 *
 * The cache uses a 32-bit hash of the packet (which can be the RSS hash) to
 * search its entries for a miniflow that matches exactly the miniflow of the
 * packet. It stores the 'dpcls_rule' (rule) that matches the miniflow.
 *
 * A cache entry holds a reference to its 'dp_netdev_flow'.
 *
 * A miniflow with a given hash can be in one of EM_FLOW_HASH_SEGS different
 * entries. The 32-bit hash is split into EM_FLOW_HASH_SEGS values (each of
 * them is EM_FLOW_HASH_SHIFT bits wide and the remainder is thrown away). Each
 * value is the index of a cache entry where the miniflow could be.
 *
 *
 * Signature match cache (SMC)
 *
 * This cache stores a 16-bit signature for each flow without storing keys, and
 * stores the corresponding 16-bit flow_table index to the 'dp_netdev_flow'.
 * Each flow thus occupies 32bit which is much more memory efficient than EMC.
 * SMC uses a set-associative design that each bucket contains
 * SMC_ENTRY_PER_BUCKET number of entries.
 * Since 16-bit flow_table index is used, if there are more than 2^16
 * dp_netdev_flow, SMC will miss them that cannot be indexed by a 16-bit value.
 *
 *
 * Thread-safety
 * =============
 *
 * Each pmd_thread has its own private exact match cache.
 * If dp_netdev_input is not called from a pmd thread, a mutex is used.
 */

#define EM_FLOW_HASH_SHIFT 13
#define EM_FLOW_HASH_ENTRIES (1u << EM_FLOW_HASH_SHIFT) //emc表大小(8192项）
#define EM_FLOW_HASH_MASK (EM_FLOW_HASH_ENTRIES - 1) //emc表hash表的mask
#define EM_FLOW_HASH_SEGS 2 //最多冲突检查多少次

/* SMC uses a set-associative design. A bucket contains a set of entries that
 * a flow item can occupy. For now, it uses one hash function rather than two
 * as for the EMC design. */
#define SMC_ENTRY_PER_BUCKET 4
#define SMC_ENTRIES (1u << 20)
#define SMC_BUCKET_CNT (SMC_ENTRIES / SMC_ENTRY_PER_BUCKET)
#define SMC_MASK (SMC_BUCKET_CNT - 1)

/* Default EMC insert probability is 1 / DEFAULT_EM_FLOW_INSERT_INV_PROB */
#define DEFAULT_EM_FLOW_INSERT_INV_PROB 100
#define DEFAULT_EM_FLOW_INSERT_MIN (UINT32_MAX /                     \
                                    DEFAULT_EM_FLOW_INSERT_INV_PROB)

struct emc_entry {
    struct dp_netdev_flow *flow;
    struct netdev_flow_key key;   /* key.hash used for emc hash value. */
};

struct emc_cache {
    struct emc_entry entries[EM_FLOW_HASH_ENTRIES];
    int sweep_idx;                /* For emc_cache_slow_sweep(). */
};

struct smc_bucket {
    uint16_t sig[SMC_ENTRY_PER_BUCKET];
    uint16_t flow_idx[SMC_ENTRY_PER_BUCKET];
};

/* Signature match cache, differentiate from EMC cache */
struct smc_cache {
    struct smc_bucket buckets[SMC_BUCKET_CNT];
};

struct dfc_cache {
    struct emc_cache emc_cache;
    struct smc_cache smc_cache;
};

/* Iterate in the exact match cache through every entry that might contain a
 * miniflow with hash 'HASH'. */
//先在实体hash&hash_mask位置检测一次，然后在(hash>>=hash_shift)&hash_mask位置检测一次（目前宏只检测两次）
#define EMC_FOR_EACH_POS_WITH_HASH(EMC, CURRENT_ENTRY, HASH)                 \
    for (uint32_t i__ = 0, srch_hash__ = (HASH);                             \
         (CURRENT_ENTRY) = &(EMC)->entries[srch_hash__ & EM_FLOW_HASH_MASK], \
         i__ < EM_FLOW_HASH_SEGS;                                            \
         i__++, srch_hash__ >>= EM_FLOW_HASH_SHIFT)

/* Simple non-wildcarding single-priority classifier. */

/* Time in microseconds between successive optimizations of the dpcls
 * subtable vector */
#define DPCLS_OPTIMIZATION_INTERVAL 1000000LL

/* Time in microseconds of the interval in which rxq processing cycles used
 * in rxq to pmd assignments is measured and stored. */
#define PMD_RXQ_INTERVAL_LEN 10000000LL

/* Number of intervals for which cycles are stored
 * and used during rxq to pmd assignment. */
#define PMD_RXQ_INTERVAL_MAX 6

struct dpcls {
    struct cmap_node node;      /* Within dp_netdev_pmd_thread.classifiers */
    odp_port_t in_port;//按入接口分类
    struct cmap subtables_map;//按不同mask分类的subtable,属dpcls_subtable类型
    struct pvector subtables;//子表
};

/* Data structure to keep packet order till fastpath processing. */
struct dp_packet_flow_map {
    struct dp_packet *packet;
    struct dp_netdev_flow *flow;
    uint16_t tcp_flags;
};

static void dpcls_init(struct dpcls *);
static void dpcls_destroy(struct dpcls *);
static void dpcls_sort_subtable_vector(struct dpcls *);
static void dpcls_insert(struct dpcls *, struct dpcls_rule *,
                         const struct netdev_flow_key *mask);
static void dpcls_remove(struct dpcls *, struct dpcls_rule *);
static bool dpcls_lookup(struct dpcls *cls,
                         const struct netdev_flow_key *keys[],
                         struct dpcls_rule **rules, size_t cnt,
                         int *num_lookups_p);

/* Set of supported meter flags */
#define DP_SUPPORTED_METER_FLAGS_MASK \
    (OFPMF13_STATS | OFPMF13_PKTPS | OFPMF13_KBPS | OFPMF13_BURST)

/* Set of supported meter band types */
#define DP_SUPPORTED_METER_BAND_TYPES           \
    ( 1 << OFPMBT13_DROP )

struct dp_meter_band {
    struct ofputil_meter_band up; /* type, prec_level, pad, rate, burst_size */
    uint32_t bucket; /* In 1/1000 packets (for PKTPS), or in bits (for KBPS) */
    uint64_t packet_count;
    uint64_t byte_count;
};

struct dp_meter {
    uint16_t flags;
    uint16_t n_bands;
    uint32_t max_delta_t;
    uint64_t used;
    uint64_t packet_count;
    uint64_t byte_count;
    struct dp_meter_band bands[];
};

struct pmd_auto_lb {
    bool auto_lb_requested;     /* Auto load balancing requested by user. */
    bool is_enabled;            /* Current status of Auto load balancing. */
    uint64_t rebalance_intvl;
    uint64_t rebalance_poll_timer;
};

/* Datapath based on the network device interface from netdev.h.
 *
 *
 * Thread-safety
 * =============
 *
 * Some members, marked 'const', are immutable.  Accessing other members
 * requires synchronization, as noted in more detail below.
 *
 * Acquisition order is, from outermost to innermost:
 *
 *    dp_netdev_mutex (global)
 *    port_mutex
 *    non_pmd_mutex
 */
//datapath对应的netdev
struct dp_netdev {
    const struct dpif_class *const class;
    const char *const name;
    struct dpif *dpif;//指向dpif，而dpif中也有指针指向dp_netdev
    struct ovs_refcount ref_cnt;
    atomic_flag destroyed;//廷后删除?

    /* Ports.
     *
     * Any lookup into 'ports' or any access to the dp_netdev_ports found
     * through 'ports' requires taking 'port_mutex'. */
    struct ovs_mutex port_mutex;
    struct hmap ports;//保存创建的port
    struct seq *port_seq;       /* Incremented whenever a port changes. */

    /* The time that a packet can wait in output batch for sending. */
    atomic_uint32_t tx_flush_interval;

    /* Meters. */
    struct ovs_mutex meter_locks[N_METER_LOCKS];
    struct dp_meter *meters[MAX_METERS]; /* Meter bands. */

    /* Probability of EMC insertions is a factor of 'emc_insert_min'.*/
    OVS_ALIGNED_VAR(CACHE_LINE_SIZE) atomic_uint32_t emc_insert_min;
    /* Enable collection of PMD performance metrics. */
    atomic_bool pmd_perf_metrics;
    /* Enable the SMC cache from ovsdb config */
    atomic_bool smc_enable_db;

    /* Protects access to ofproto-dpif-upcall interface during revalidator
     * thread synchronization. */
    struct fat_rwlock upcall_rwlock;
    //upcall回调
    upcall_callback *upcall_cb;  /* Callback function for executing upcalls. */
    //upcall 对应的参数
    void *upcall_aux;

    /* Callback function for notifying the purging of dp flows (during
     * reseting pmd deletion). */
    dp_purge_callback *dp_purge_cb;
    void *dp_purge_aux;

    /* Stores all 'struct dp_netdev_pmd_thread's. */
    struct cmap poll_threads;//用于存储当前dp的所有dp_netdev_pmd_thread
    /* id pool for per thread static_tx_qid. */
    struct id_pool *tx_qid_pool;
    struct ovs_mutex tx_qid_pool_mutex;
    /* Use measured cycles for rxq to pmd assignment. */
    bool pmd_rxq_assign_cyc;

    /* Protects the access of the 'struct dp_netdev_pmd_thread'
     * instance for non-pmd thread. */
    struct ovs_mutex non_pmd_mutex;

    /* Each pmd thread will store its pointer to
     * 'struct dp_netdev_pmd_thread' in 'per_pmd_key'. */
    ovsthread_key_t per_pmd_key;

    struct seq *reconfigure_seq;//重配置序列器（读取此值，用于获取当前重配置要求的序列号）
    uint64_t last_reconfigure_seq;//上次我们完成重配置后的序列号(与reconfigure_seq决定是否需要重配置）

    /* Cpu mask for pin of pmd threads. */
    char *pmd_cmask;//pmd的cpu绑定掩码

    uint64_t last_tnl_conf_seq;

    struct conntrack *conntrack;//提供连接跟踪功能（每个datapath一个这张表）
    struct pmd_auto_lb pmd_alb;
};

static void meter_lock(const struct dp_netdev *dp, uint32_t meter_id)
    OVS_ACQUIRES(dp->meter_locks[meter_id % N_METER_LOCKS])
{
    ovs_mutex_lock(&dp->meter_locks[meter_id % N_METER_LOCKS]);
}

static void meter_unlock(const struct dp_netdev *dp, uint32_t meter_id)
    OVS_RELEASES(dp->meter_locks[meter_id % N_METER_LOCKS])
{
    ovs_mutex_unlock(&dp->meter_locks[meter_id % N_METER_LOCKS]);
}


static struct dp_netdev_port *dp_netdev_lookup_port(const struct dp_netdev *dp,
                                                    odp_port_t)
    OVS_REQUIRES(dp->port_mutex);

enum rxq_cycles_counter_type {
    RXQ_CYCLES_PROC_CURR,       /* Cycles spent successfully polling and
                                   processing packets during the current
                                   interval. */
    RXQ_CYCLES_PROC_HIST,       /* Total cycles of all intervals that are used
                                   during rxq to pmd assignment. */
    RXQ_N_CYCLES
};

enum {
    DP_NETDEV_FLOW_OFFLOAD_OP_ADD,
    DP_NETDEV_FLOW_OFFLOAD_OP_MOD,
    DP_NETDEV_FLOW_OFFLOAD_OP_DEL,
};

struct dp_flow_offload_item {
    struct dp_netdev_pmd_thread *pmd;
    struct dp_netdev_flow *flow;
    int op;
    struct match match;
    struct nlattr *actions;
    size_t actions_len;

    struct ovs_list node;
};

struct dp_flow_offload {
    struct ovs_mutex mutex;
    struct ovs_list list;
    pthread_cond_t cond;
};

//记录需要offload的流
static struct dp_flow_offload dp_flow_offload = {
    .mutex = OVS_MUTEX_INITIALIZER,
    .list  = OVS_LIST_INITIALIZER(&dp_flow_offload.list),
};

static struct ovsthread_once offload_thread_once
    = OVSTHREAD_ONCE_INITIALIZER;

#define XPS_TIMEOUT 500000LL    /* In microseconds. */

/* Contained by struct dp_netdev_port's 'rxqs' member.  */
struct dp_netdev_rxq {
    struct dp_netdev_port *port;
    struct netdev_rxq *rx;
    //负责收取此队列的core_id
    unsigned core_id;                  /* Core to which this queue should be
                                          pinned. OVS_CORE_UNSPEC if the
                                          queue doesn't need to be pinned to a
                                          particular core. */
    unsigned intrvl_idx;               /* Write index for 'cycles_intrvl'. */
    struct dp_netdev_pmd_thread *pmd;  /* pmd thread that polls this queue. */
    bool is_vhost;                     /* Is rxq of a vhost port. */

    /* Counters of cycles spent successfully polling and processing pkts. */
    atomic_ullong cycles[RXQ_N_CYCLES];
    /* We store PMD_RXQ_INTERVAL_MAX intervals of data for an rxq and then
       sum them to yield the cycles used for an rxq. */
    atomic_ullong cycles_intrvl[PMD_RXQ_INTERVAL_MAX];
};

/* A port in a netdev-based datapath. */
struct dp_netdev_port {
    odp_port_t port_no;//port编号
    bool dynamic_txqs;          /* If true XPS will be used. */
    bool need_reconfigure;      /* True if we should reconfigure netdev. */
    struct netdev *netdev;//port对应的netdev
    struct hmap_node node;      /* Node in dp_netdev's 'ports'. */
    struct netdev_saved_flags *sf;//保存的flags
    //port的收队列数组
    struct dp_netdev_rxq *rxqs;
    //port的收队列数组大小
    unsigned n_rxq;             /* Number of elements in 'rxqs' */
    unsigned *txq_used;         /* Number of threads that use each tx queue. */
    struct ovs_mutex txq_used_mutex;
    bool emc_enabled;           /* If true EMC will be used. */
    //netdev class类型
    char *type;                 /* Port type as requested by user. */
    //收队列的cpu亲昵性
    char *rxq_affinity_list;    /* Requested affinity of rx queues. */
};

/* Contained by struct dp_netdev_flow's 'stats' member.  */
struct dp_netdev_flow_stats {
    atomic_llong used;             /* Last used time, in monotonic msecs. */
    atomic_ullong packet_count;    /* Number of packets matched. */ //此条流命中的报文数
    atomic_ullong byte_count;      /* Number of bytes matched. */ //此条流命中的字节数
    atomic_uint16_t tcp_flags;     /* Bitwise-OR of seen tcp_flags values. */ //此条流命中的tcp flags
};

/* A flow in 'dp_netdev_pmd_thread's 'flow_table'.
 *
 *
 * Thread-safety
 * =============
 *
 * Except near the beginning or ending of its lifespan, rule 'rule' belongs to
 * its pmd thread's classifier.  The text below calls this classifier 'cls'.
 *
 * Motivation
 * ----------
 *
 * The thread safety rules described here for "struct dp_netdev_flow" are
 * motivated by two goals:
 *
 *    - Prevent threads that read members of "struct dp_netdev_flow" from
 *      reading bad data due to changes by some thread concurrently modifying
 *      those members.
 *
 *    - Prevent two threads making changes to members of a given "struct
 *      dp_netdev_flow" from interfering with each other.
 *
 *
 * Rules
 * -----
 *
 * A flow 'flow' may be accessed without a risk of being freed during an RCU
 * grace period.  Code that needs to hold onto a flow for a while
 * should try incrementing 'flow->ref_cnt' with dp_netdev_flow_ref().
 *
 * 'flow->ref_cnt' protects 'flow' from being freed.  It doesn't protect the
 * flow from being deleted from 'cls' and it doesn't protect members of 'flow'
 * from modification.
 *
 * Some members, marked 'const', are immutable.  Accessing other members
 * requires synchronization, as noted in more detail below.
 */
struct dp_netdev_flow {
    const struct flow flow;      /* Unmasked flow that created this entry. */
    /* Hash table index by unmasked flow. */
    const struct cmap_node node; /* In owning dp_netdev_pmd_thread's */
                                 /* 'flow_table'. */
    const struct cmap_node mark_node; /* In owning flow_mark's mark_to_flow */
    const ovs_u128 ufid;         /* Unique flow identifier. */
    const ovs_u128 mega_ufid;    /* Unique mega flow identifier. */
    const unsigned pmd_id;       /* The 'core_id' of pmd thread owning this */
                                 /* flow. */

    /* Number of references.
     * The classifier owns one reference.
     * Any thread trying to keep a rule from being freed should hold its own
     * reference. */
    struct ovs_refcount ref_cnt;

    bool dead;
    uint32_t mark;               /* Unique flow mark assigned to a flow */

    /* Statistics. */
    struct dp_netdev_flow_stats stats;

    /* Actions. */
    OVSRCU_TYPE(struct dp_netdev_actions *) actions;//flow中的actions

    /* While processing a group of input packets, the datapath uses the next
     * member to store a pointer to the output batch for the flow.  It is
     * reset after the batch has been sent out (See dp_netdev_queue_batches(),
     * packet_batch_per_flow_init() and packet_batch_per_flow_execute()). */
    struct packet_batch_per_flow *batch;//此flow对应的batch,用于指针此需要执行同一个flow的packets

    /* Packet classification. */
    struct dpcls_rule cr;        /* In owning dp_netdev's 'cls'. */ //记录cls的规则
    /* 'cr' must be the last member. */
};

static void dp_netdev_flow_unref(struct dp_netdev_flow *);
static bool dp_netdev_flow_ref(struct dp_netdev_flow *);
static int dpif_netdev_flow_from_nlattrs(const struct nlattr *, uint32_t,
                                         struct flow *, bool);

/* A set of datapath actions within a "struct dp_netdev_flow".
 *
 *
 * Thread-safety
 * =============
 *
 * A struct dp_netdev_actions 'actions' is protected with RCU. */
struct dp_netdev_actions {
    /* These members are immutable: they do not change during the struct's
     * lifetime.  */
    unsigned int size;          /* Size of 'actions', in bytes. */
    struct nlattr actions[];    /* Sequence of OVS_ACTION_ATTR_* attributes. */
};

struct dp_netdev_actions *dp_netdev_actions_create(const struct nlattr *,
                                                   size_t);
struct dp_netdev_actions *dp_netdev_flow_get_actions(
    const struct dp_netdev_flow *);
static void dp_netdev_actions_free(struct dp_netdev_actions *);

struct polled_queue {
    struct dp_netdev_rxq *rxq;//收队列
    odp_port_t port_no;
    bool emc_enabled;
    bool rxq_enabled;
    uint64_t change_seq;
};

/* Contained by struct dp_netdev_pmd_thread's 'poll_list' member. */
struct rxq_poll {
    struct dp_netdev_rxq *rxq;
    struct hmap_node node;
};

/* Contained by struct dp_netdev_pmd_thread's 'send_port_cache',
 * 'tnl_port_cache' or 'tx_ports'. */
struct tx_port {
    struct dp_netdev_port *port;//port从属的设备
    int qid;//tx队列的队列id
    long long last_used;//最近一次使用的时间点
    struct hmap_node node;
    long long flush_time;
    struct dp_packet_batch output_pkts;
    struct dp_netdev_rxq *output_pkts_rxqs[NETDEV_MAX_BURST];
};

/* A set of properties for the current processing loop that is not directly
 * associated with the pmd thread itself, but with the packets being
 * processed or the short-term system configuration (for example, time).
 * Contained by struct dp_netdev_pmd_thread's 'ctx' member. */
struct dp_netdev_pmd_thread_ctx {
    /* Latest measured time. See 'pmd_thread_ctx_time_update()'. */
    long long now;
    /* RX queue from which last packet was received. */
    struct dp_netdev_rxq *last_rxq;
    /* EMC insertion probability context for the current processing cycle. */
    uint32_t emc_insert_min;
};

/* PMD: Poll modes drivers.  PMD accesses devices via polling to eliminate
 * the performance overhead of interrupt processing.  Therefore netdev can
 * not implement rx-wait for these devices.  dpif-netdev needs to poll
 * these device to check for recv buffer.  pmd-thread does polling for
 * devices assigned to itself.
 *
 * DPDK used PMD for accessing NIC.
 *
 * Note, instance with cpu core id NON_PMD_CORE_ID will be reserved for
 * I/O of all non-pmd threads.  There will be no actual thread created
 * for the instance.
 *
 * Each struct has its own flow cache and classifier per managed ingress port.
 * For packets received on ingress port, a look up is done on corresponding PMD
 * thread's flow cache and in case of a miss, lookup is performed in the
 * corresponding classifier of port.  Packets are executed with the found
 * actions in either case.
 * */
struct dp_netdev_pmd_thread {
    struct dp_netdev *dp;//属于哪个dp
    struct ovs_refcount ref_cnt;    /* Every reference must be refcount'ed. */
    struct cmap_node node;          /* In 'dp->poll_threads'. */

    /* Per thread exact-match cache.  Note, the instance for cpu core
     * NON_PMD_CORE_ID can be accessed by multiple threads, and thusly
     * need to be protected by 'non_pmd_mutex'.  Every other instance
     * will only be accessed by its own pmd thread. */
    //精确匹配缓存（每线程一个）
    OVS_ALIGNED_VAR(CACHE_LINE_SIZE) struct dfc_cache flow_cache;

    /* Flow-Table and classifiers
     *
     * Writers of 'flow_table' must take the 'flow_mutex'.  Corresponding
     * changes to 'classifiers' must be made while still holding the
     * 'flow_mutex'.
     */
    struct ovs_mutex flow_mutex;
    struct cmap flow_table OVS_GUARDED; /* Flow table. */

    /* One classifier per in_port polled by the pmd */
    struct cmap classifiers;
    /* Periodically sort subtable vectors according to hit frequencies */
    long long int next_optimization;
    /* End of the next time interval for which processing cycles
       are stored for each polled rxq. */
    long long int rxq_next_cycle_store;

    /* Last interval timestamp. */
    uint64_t intrvl_tsc_prev;
    /* Last interval cycles. */
    atomic_ullong intrvl_cycles;

    /* Current context of the PMD thread. */
    struct dp_netdev_pmd_thread_ctx ctx;

    struct seq *reload_seq;
    uint64_t last_reload_seq;

    /* These are atomic variables used as a synchronization and configuration
     * points for thread reload/exit.
     *
     * 'reload' atomic is the main one and it's used as a memory
     * synchronization point for all other knobs and data.
     *
     * For a thread that requests PMD reload:
     *
     *   * All changes that should be visible to the PMD thread must be made
     *     before setting the 'reload'.  These changes could use any memory
     *     ordering model including 'relaxed'.
     *   * Setting the 'reload' atomic should occur in the same thread where
     *     all other PMD configuration options updated.
     *   * Setting the 'reload' atomic should be done with 'release' memory
     *     ordering model or stricter.  This will guarantee that all previous
     *     changes (including non-atomic and 'relaxed') will be visible to
     *     the PMD thread.
     *   * To check that reload is done, thread should poll the 'reload' atomic
     *     to become 'false'.  Polling should be done with 'acquire' memory
     *     ordering model or stricter.  This ensures that PMD thread completed
     *     the reload process.
     *
     * For the PMD thread:
     *
     *   * PMD thread should read 'reload' atomic with 'acquire' memory
     *     ordering model or stricter.  This will guarantee that all changes
     *     made before setting the 'reload' in the requesting thread will be
     *     visible to the PMD thread.
     *   * All other configuration data could be read with any memory
     *     ordering model (including non-atomic and 'relaxed') but *only after*
     *     reading the 'reload' atomic set to 'true'.
     *   * When the PMD reload done, PMD should (optionally) set all the below
     *     knobs except the 'reload' to their default ('false') values and
     *     (mandatory), as the last step, set the 'reload' to 'false' using
     *     'release' memory ordering model or stricter.  This will inform the
     *     requesting thread that PMD has completed a reload cycle.
     */
    atomic_bool reload;             /* Do we need to reload ports? */
    atomic_bool wait_for_reload;    /* Can we busy wait for the next reload? */
    atomic_bool reload_tx_qid;      /* Do we need to reload static_tx_qid? */
    atomic_bool exit;               /* For terminating the pmd thread. */

    pthread_t thread;
    unsigned core_id;               /* CPU core id of this pmd thread. */
    int numa_id;                    /* numa node id of this pmd thread. */
    bool isolated;

    /* Queue id used by this pmd thread to send packets on all netdevs if
     * XPS disabled for this netdev. All static_tx_qid's are unique and less
     * than 'cmap_count(dp->poll_threads)'. */
    uint32_t static_tx_qid;

    /* Number of filled output batches. */
    int n_output_batches;

    struct ovs_mutex port_mutex;    /* Mutex for 'poll_list' and 'tx_ports'. */
    /* List of rx queues to poll. */
    struct hmap poll_list OVS_GUARDED;
    /* Map of 'tx_port's used for transmission.  Written by the main thread,
     * read by the pmd thread. */
    struct hmap tx_ports OVS_GUARDED;

    /* These are thread-local copies of 'tx_ports'.  One contains only tunnel
     * ports (that support push_tunnel/pop_tunnel), the other contains ports
     * with at least one txq (that support send).  A port can be in both.
     *
     * There are two separate maps to make sure that we don't try to execute
     * OUTPUT on a device which has 0 txqs or PUSH/POP on a non-tunnel device.
     *
     * The instances for cpu core NON_PMD_CORE_ID can be accessed by multiple
     * threads, and thusly need to be protected by 'non_pmd_mutex'.  Every
     * other instance will only be accessed by its own pmd thread. */
    struct hmap tnl_port_cache;//隧道口集合
    struct hmap send_port_cache;

    /* Keep track of detailed PMD performance statistics. */
    struct pmd_perf_stats perf_stats;

    /* Stats from previous iteration used by automatic pmd
     * load balance logic. */
    uint64_t prev_stats[PMD_N_STATS];
    atomic_count pmd_overloaded;

    /* Set to true if the pmd thread needs to be reloaded. */
    bool need_reload;
};

/* Interface to netdev-based datapath. */
struct dpif_netdev {
    struct dpif dpif;//要返回的结构
    struct dp_netdev *dp;//基类
    uint64_t last_port_seq;
};

static int get_port_by_number(struct dp_netdev *dp, odp_port_t port_no,
                              struct dp_netdev_port **portp)
    OVS_REQUIRES(dp->port_mutex);
static int get_port_by_name(struct dp_netdev *dp, const char *devname,
                            struct dp_netdev_port **portp)
    OVS_REQUIRES(dp->port_mutex);
static void dp_netdev_free(struct dp_netdev *)
    OVS_REQUIRES(dp_netdev_mutex);
static int do_add_port(struct dp_netdev *dp, const char *devname,
                       const char *type, odp_port_t port_no)
    OVS_REQUIRES(dp->port_mutex);
static void do_del_port(struct dp_netdev *dp, struct dp_netdev_port *)
    OVS_REQUIRES(dp->port_mutex);
static int dpif_netdev_open(const struct dpif_class *, const char *name,
                            bool create, struct dpif **);
static void dp_netdev_execute_actions(struct dp_netdev_pmd_thread *pmd,
                                      struct dp_packet_batch *,
                                      bool should_steal,
                                      const struct flow *flow,
                                      const struct nlattr *actions,
                                      size_t actions_len);
static void dp_netdev_input(struct dp_netdev_pmd_thread *,
                            struct dp_packet_batch *, odp_port_t port_no);
static void dp_netdev_recirculate(struct dp_netdev_pmd_thread *,
                                  struct dp_packet_batch *);

static void dp_netdev_disable_upcall(struct dp_netdev *);
static void dp_netdev_pmd_reload_done(struct dp_netdev_pmd_thread *pmd);
static void dp_netdev_configure_pmd(struct dp_netdev_pmd_thread *pmd,
                                    struct dp_netdev *dp, unsigned core_id,
                                    int numa_id);
static void dp_netdev_destroy_pmd(struct dp_netdev_pmd_thread *pmd);
static void dp_netdev_set_nonpmd(struct dp_netdev *dp)
    OVS_REQUIRES(dp->port_mutex);

static void *pmd_thread_main(void *);
static struct dp_netdev_pmd_thread *dp_netdev_get_pmd(struct dp_netdev *dp,
                                                      unsigned core_id);
static struct dp_netdev_pmd_thread *
dp_netdev_pmd_get_next(struct dp_netdev *dp, struct cmap_position *pos);
static void dp_netdev_del_pmd(struct dp_netdev *dp,
                              struct dp_netdev_pmd_thread *pmd);
static void dp_netdev_destroy_all_pmds(struct dp_netdev *dp, bool non_pmd);
static void dp_netdev_pmd_clear_ports(struct dp_netdev_pmd_thread *pmd);
static void dp_netdev_add_port_tx_to_pmd(struct dp_netdev_pmd_thread *pmd,
                                         struct dp_netdev_port *port)
    OVS_REQUIRES(pmd->port_mutex);
static void dp_netdev_del_port_tx_from_pmd(struct dp_netdev_pmd_thread *pmd,
                                           struct tx_port *tx)
    OVS_REQUIRES(pmd->port_mutex);
static void dp_netdev_add_rxq_to_pmd(struct dp_netdev_pmd_thread *pmd,
                                     struct dp_netdev_rxq *rxq)
    OVS_REQUIRES(pmd->port_mutex);
static void dp_netdev_del_rxq_from_pmd(struct dp_netdev_pmd_thread *pmd,
                                       struct rxq_poll *poll)
    OVS_REQUIRES(pmd->port_mutex);
static int
dp_netdev_pmd_flush_output_packets(struct dp_netdev_pmd_thread *pmd,
                                   bool force);

static void reconfigure_datapath(struct dp_netdev *dp)
    OVS_REQUIRES(dp->port_mutex);
static bool dp_netdev_pmd_try_ref(struct dp_netdev_pmd_thread *pmd);
static void dp_netdev_pmd_unref(struct dp_netdev_pmd_thread *pmd);
static void dp_netdev_pmd_flow_flush(struct dp_netdev_pmd_thread *pmd);
static void pmd_load_cached_ports(struct dp_netdev_pmd_thread *pmd)
    OVS_REQUIRES(pmd->port_mutex);
static inline void
dp_netdev_pmd_try_optimize(struct dp_netdev_pmd_thread *pmd,
                           struct polled_queue *poll_list, int poll_cnt);
static void
dp_netdev_rxq_set_cycles(struct dp_netdev_rxq *rx,
                         enum rxq_cycles_counter_type type,
                         unsigned long long cycles);
static uint64_t
dp_netdev_rxq_get_cycles(struct dp_netdev_rxq *rx,
                         enum rxq_cycles_counter_type type);
static void
dp_netdev_rxq_set_intrvl_cycles(struct dp_netdev_rxq *rx,
                           unsigned long long cycles);
static uint64_t
dp_netdev_rxq_get_intrvl_cycles(struct dp_netdev_rxq *rx, unsigned idx);
static void
dpif_netdev_xps_revalidate_pmd(const struct dp_netdev_pmd_thread *pmd,
                               bool purge);
static int dpif_netdev_xps_get_tx_qid(const struct dp_netdev_pmd_thread *pmd,
                                      struct tx_port *tx);

static inline bool emc_entry_alive(struct emc_entry *ce);
static void emc_clear_entry(struct emc_entry *ce);
static void smc_clear_entry(struct smc_bucket *b, int idx);

static void dp_netdev_request_reconfigure(struct dp_netdev *dp);
static inline bool
pmd_perf_metrics_enabled(const struct dp_netdev_pmd_thread *pmd);
static void queue_netdev_flow_del(struct dp_netdev_pmd_thread *pmd,
                                  struct dp_netdev_flow *flow);

static void
emc_cache_init(struct emc_cache *flow_cache)
{
    int i;

    flow_cache->sweep_idx = 0;
    for (i = 0; i < ARRAY_SIZE(flow_cache->entries); i++) {
        flow_cache->entries[i].flow = NULL;
        flow_cache->entries[i].key.hash = 0;
        flow_cache->entries[i].key.len = sizeof(struct miniflow);
        flowmap_init(&flow_cache->entries[i].key.mf.map);
    }
}

//删除emc缓存中所有内容（采用rcu延迟释放）
static void
smc_cache_init(struct smc_cache *smc_cache)
{
    int i, j;
    for (i = 0; i < SMC_BUCKET_CNT; i++) {
        for (j = 0; j < SMC_ENTRY_PER_BUCKET; j++) {
            smc_cache->buckets[i].flow_idx[j] = UINT16_MAX;
        }
    }
}

static void
dfc_cache_init(struct dfc_cache *flow_cache)
{
    emc_cache_init(&flow_cache->emc_cache);
    smc_cache_init(&flow_cache->smc_cache);
}

static void
emc_cache_uninit(struct emc_cache *flow_cache)
{
    int i;

    for (i = 0; i < ARRAY_SIZE(flow_cache->entries); i++) {
        emc_clear_entry(&flow_cache->entries[i]);
    }
}

static void
smc_cache_uninit(struct smc_cache *smc)
{
    int i, j;

    for (i = 0; i < SMC_BUCKET_CNT; i++) {
        for (j = 0; j < SMC_ENTRY_PER_BUCKET; j++) {
            smc_clear_entry(&(smc->buckets[i]), j);
        }
    }
}

static void
dfc_cache_uninit(struct dfc_cache *flow_cache)
{
    smc_cache_uninit(&flow_cache->smc_cache);
    emc_cache_uninit(&flow_cache->emc_cache);
}

/* Check and clear dead flow references slowly (one entry at each
 * invocation).  */
static void
emc_cache_slow_sweep(struct emc_cache *flow_cache)
{
    struct emc_entry *entry = &flow_cache->entries[flow_cache->sweep_idx];

    if (!emc_entry_alive(entry)) {
        emc_clear_entry(entry);
    }
    flow_cache->sweep_idx = (flow_cache->sweep_idx + 1) & EM_FLOW_HASH_MASK;
}

/* Updates the time in PMD threads context and should be called in three cases:
 *
 *     1. PMD structure initialization:
 *         - dp_netdev_configure_pmd()
 *
 *     2. Before processing of the new packet batch:
 *         - dpif_netdev_execute()
 *         - dp_netdev_process_rxq_port()
 *
 *     3. At least once per polling iteration in main polling threads if no
 *        packets received on current iteration:
 *         - dpif_netdev_run()
 *         - pmd_thread_main()
 *
 * 'pmd->ctx.now' should be used without update in all other cases if possible.
 */
static inline void
pmd_thread_ctx_time_update(struct dp_netdev_pmd_thread *pmd)
{
    pmd->ctx.now = time_usec();
}

/* Returns true if 'dpif' is a netdev or dummy dpif, false otherwise. */
bool
dpif_is_netdev(const struct dpif *dpif)
{
    return dpif->dpif_class->open == dpif_netdev_open;
}

static struct dpif_netdev *
dpif_netdev_cast(const struct dpif *dpif)
{
    ovs_assert(dpif_is_netdev(dpif));
    return CONTAINER_OF(dpif, struct dpif_netdev, dpif);
}

static struct dp_netdev *
get_dp_netdev(const struct dpif *dpif)
{
    return dpif_netdev_cast(dpif)->dp;
}

enum pmd_info_type {
    PMD_INFO_SHOW_STATS,  /* Show how cpu cycles are spent. */
    PMD_INFO_CLEAR_STATS, /* Set the cycles count to 0. */
    PMD_INFO_SHOW_RXQ,    /* Show poll lists of pmd threads. */
    PMD_INFO_PERF_SHOW,   /* Show pmd performance details. */
};

static void
format_pmd_thread(struct ds *reply, struct dp_netdev_pmd_thread *pmd)
{
    ds_put_cstr(reply, (pmd->core_id == NON_PMD_CORE_ID)
                        ? "main thread" : "pmd thread");
    if (pmd->numa_id != OVS_NUMA_UNSPEC) {
        ds_put_format(reply, " numa_id %d", pmd->numa_id);
    }
    if (pmd->core_id != OVS_CORE_UNSPEC && pmd->core_id != NON_PMD_CORE_ID) {
        ds_put_format(reply, " core_id %u", pmd->core_id);
    }
    ds_put_cstr(reply, ":\n");
}

static void
pmd_info_show_stats(struct ds *reply,
                    struct dp_netdev_pmd_thread *pmd)
{
    uint64_t stats[PMD_N_STATS];
    uint64_t total_cycles, total_packets;
    double passes_per_pkt = 0;
    double lookups_per_hit = 0;
    double packets_per_batch = 0;

    pmd_perf_read_counters(&pmd->perf_stats, stats);
    total_cycles = stats[PMD_CYCLES_ITER_IDLE]
                         + stats[PMD_CYCLES_ITER_BUSY];
    total_packets = stats[PMD_STAT_RECV];

    format_pmd_thread(reply, pmd);

    if (total_packets > 0) {
        passes_per_pkt = (total_packets + stats[PMD_STAT_RECIRC])
                            / (double) total_packets;
    }
    if (stats[PMD_STAT_MASKED_HIT] > 0) {
        lookups_per_hit = stats[PMD_STAT_MASKED_LOOKUP]
                            / (double) stats[PMD_STAT_MASKED_HIT];
    }
    if (stats[PMD_STAT_SENT_BATCHES] > 0) {
        packets_per_batch = stats[PMD_STAT_SENT_PKTS]
                            / (double) stats[PMD_STAT_SENT_BATCHES];
    }

    ds_put_format(reply,
                  "  packets received: %"PRIu64"\n"
                  "  packet recirculations: %"PRIu64"\n"
                  "  avg. datapath passes per packet: %.02f\n"
                  "  emc hits: %"PRIu64"\n"
                  "  smc hits: %"PRIu64"\n"
                  "  megaflow hits: %"PRIu64"\n"
                  "  avg. subtable lookups per megaflow hit: %.02f\n"
                  "  miss with success upcall: %"PRIu64"\n"
                  "  miss with failed upcall: %"PRIu64"\n"
                  "  avg. packets per output batch: %.02f\n",
                  total_packets, stats[PMD_STAT_RECIRC],
                  passes_per_pkt, stats[PMD_STAT_EXACT_HIT],
                  stats[PMD_STAT_SMC_HIT],
                  stats[PMD_STAT_MASKED_HIT], lookups_per_hit,
                  stats[PMD_STAT_MISS], stats[PMD_STAT_LOST],
                  packets_per_batch);

    if (total_cycles == 0) {
        return;
    }

    ds_put_format(reply,
                  "  idle cycles: %"PRIu64" (%.02f%%)\n"
                  "  processing cycles: %"PRIu64" (%.02f%%)\n",
                  stats[PMD_CYCLES_ITER_IDLE],
                  stats[PMD_CYCLES_ITER_IDLE] / (double) total_cycles * 100,
                  stats[PMD_CYCLES_ITER_BUSY],
                  stats[PMD_CYCLES_ITER_BUSY] / (double) total_cycles * 100);

    if (total_packets == 0) {
        return;
    }

    ds_put_format(reply,
                  "  avg cycles per packet: %.02f (%"PRIu64"/%"PRIu64")\n",
                  total_cycles / (double) total_packets,
                  total_cycles, total_packets);

    ds_put_format(reply,
                  "  avg processing cycles per packet: "
                  "%.02f (%"PRIu64"/%"PRIu64")\n",
                  stats[PMD_CYCLES_ITER_BUSY] / (double) total_packets,
                  stats[PMD_CYCLES_ITER_BUSY], total_packets);
}

static void
pmd_info_show_perf(struct ds *reply,
                   struct dp_netdev_pmd_thread *pmd,
                   struct pmd_perf_params *par)
{
    if (pmd->core_id != NON_PMD_CORE_ID) {
        char *time_str =
                xastrftime_msec("%H:%M:%S.###", time_wall_msec(), true);
        long long now = time_msec();
        double duration = (now - pmd->perf_stats.start_ms) / 1000.0;

        ds_put_cstr(reply, "\n");
        ds_put_format(reply, "Time: %s\n", time_str);
        ds_put_format(reply, "Measurement duration: %.3f s\n", duration);
        ds_put_cstr(reply, "\n");
        format_pmd_thread(reply, pmd);
        ds_put_cstr(reply, "\n");
        pmd_perf_format_overall_stats(reply, &pmd->perf_stats, duration);
        if (pmd_perf_metrics_enabled(pmd)) {
            /* Prevent parallel clearing of perf metrics. */
            ovs_mutex_lock(&pmd->perf_stats.clear_mutex);
            if (par->histograms) {
                ds_put_cstr(reply, "\n");
                pmd_perf_format_histograms(reply, &pmd->perf_stats);
            }
            if (par->iter_hist_len > 0) {
                ds_put_cstr(reply, "\n");
                pmd_perf_format_iteration_history(reply, &pmd->perf_stats,
                        par->iter_hist_len);
            }
            if (par->ms_hist_len > 0) {
                ds_put_cstr(reply, "\n");
                pmd_perf_format_ms_history(reply, &pmd->perf_stats,
                        par->ms_hist_len);
            }
            ovs_mutex_unlock(&pmd->perf_stats.clear_mutex);
        }
        free(time_str);
    }
}

static int
compare_poll_list(const void *a_, const void *b_)
{
    const struct rxq_poll *a = a_;
    const struct rxq_poll *b = b_;

    const char *namea = netdev_rxq_get_name(a->rxq->rx);
    const char *nameb = netdev_rxq_get_name(b->rxq->rx);

    int cmp = strcmp(namea, nameb);
    if (!cmp) {
        return netdev_rxq_get_queue_id(a->rxq->rx)
               - netdev_rxq_get_queue_id(b->rxq->rx);
    } else {
        return cmp;
    }
}

static void
sorted_poll_list(struct dp_netdev_pmd_thread *pmd, struct rxq_poll **list,
                 size_t *n)
    OVS_REQUIRES(pmd->port_mutex)
{
    struct rxq_poll *ret, *poll;
    size_t i;

    *n = hmap_count(&pmd->poll_list);
    if (!*n) {
        ret = NULL;
    } else {
        ret = xcalloc(*n, sizeof *ret);
        i = 0;
        HMAP_FOR_EACH (poll, node, &pmd->poll_list) {
            ret[i] = *poll;
            i++;
        }
        ovs_assert(i == *n);
        qsort(ret, *n, sizeof *ret, compare_poll_list);
    }

    *list = ret;
}

static void
pmd_info_show_rxq(struct ds *reply, struct dp_netdev_pmd_thread *pmd)
{
    if (pmd->core_id != NON_PMD_CORE_ID) {
        struct rxq_poll *list;
        size_t n_rxq;
        uint64_t total_cycles = 0;

        ds_put_format(reply,
                      "pmd thread numa_id %d core_id %u:\n  isolated : %s\n",
                      pmd->numa_id, pmd->core_id, (pmd->isolated)
                                                  ? "true" : "false");

        ovs_mutex_lock(&pmd->port_mutex);
        sorted_poll_list(pmd, &list, &n_rxq);

        /* Get the total pmd cycles for an interval. */
        atomic_read_relaxed(&pmd->intrvl_cycles, &total_cycles);
        /* Estimate the cycles to cover all intervals. */
        total_cycles *= PMD_RXQ_INTERVAL_MAX;

        for (int i = 0; i < n_rxq; i++) {
            struct dp_netdev_rxq *rxq = list[i].rxq;
            const char *name = netdev_rxq_get_name(rxq->rx);
            uint64_t proc_cycles = 0;

            for (int j = 0; j < PMD_RXQ_INTERVAL_MAX; j++) {
                proc_cycles += dp_netdev_rxq_get_intrvl_cycles(rxq, j);
            }
            ds_put_format(reply, "  port: %-16s  queue-id: %2d", name,
                          netdev_rxq_get_queue_id(list[i].rxq->rx));
            ds_put_format(reply, " %s", netdev_rxq_enabled(list[i].rxq->rx)
                                        ? "(enabled) " : "(disabled)");
            ds_put_format(reply, "  pmd usage: ");
            if (total_cycles) {
                ds_put_format(reply, "%2"PRIu64"",
                              proc_cycles * 100 / total_cycles);
                ds_put_cstr(reply, " %");
            } else {
                ds_put_format(reply, "%s", "NOT AVAIL");
            }
            ds_put_cstr(reply, "\n");
        }
        ovs_mutex_unlock(&pmd->port_mutex);
        free(list);
    }
}

static int
compare_poll_thread_list(const void *a_, const void *b_)
{
    const struct dp_netdev_pmd_thread *a, *b;

    a = *(struct dp_netdev_pmd_thread **)a_;
    b = *(struct dp_netdev_pmd_thread **)b_;

    if (a->core_id < b->core_id) {
        return -1;
    }
    if (a->core_id > b->core_id) {
        return 1;
    }
    return 0;
}

/* Create a sorted list of pmd's from the dp->poll_threads cmap. We can use
 * this list, as long as we do not go to quiescent state. */
static void
sorted_poll_thread_list(struct dp_netdev *dp,
                        struct dp_netdev_pmd_thread ***list,
                        size_t *n)
{
    struct dp_netdev_pmd_thread *pmd;
    struct dp_netdev_pmd_thread **pmd_list;
    size_t k = 0, n_pmds;

    n_pmds = cmap_count(&dp->poll_threads);
    pmd_list = xcalloc(n_pmds, sizeof *pmd_list);

    CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
        if (k >= n_pmds) {
            break;
        }
        pmd_list[k++] = pmd;
    }

    qsort(pmd_list, k, sizeof *pmd_list, compare_poll_thread_list);

    *list = pmd_list;
    *n = k;
}

static void
dpif_netdev_pmd_rebalance(struct unixctl_conn *conn, int argc,
                          const char *argv[], void *aux OVS_UNUSED)
{
    struct ds reply = DS_EMPTY_INITIALIZER;
    struct dp_netdev *dp = NULL;

    ovs_mutex_lock(&dp_netdev_mutex);

    if (argc == 2) {
        dp = shash_find_data(&dp_netdevs, argv[1]);
    } else if (shash_count(&dp_netdevs) == 1) {
        /* There's only one datapath */
        dp = shash_first(&dp_netdevs)->data;
    }

    if (!dp) {
        ovs_mutex_unlock(&dp_netdev_mutex);
        unixctl_command_reply_error(conn,
                                    "please specify an existing datapath");
        return;
    }

    dp_netdev_request_reconfigure(dp);
    ovs_mutex_unlock(&dp_netdev_mutex);
    ds_put_cstr(&reply, "pmd rxq rebalance requested.\n");
    unixctl_command_reply(conn, ds_cstr(&reply));
    ds_destroy(&reply);
}

static void
dpif_netdev_pmd_info(struct unixctl_conn *conn, int argc, const char *argv[],
                     void *aux)
{
    struct ds reply = DS_EMPTY_INITIALIZER;
    struct dp_netdev_pmd_thread **pmd_list;
    struct dp_netdev *dp = NULL;
    enum pmd_info_type type = *(enum pmd_info_type *) aux;
    unsigned int core_id;
    bool filter_on_pmd = false;
    size_t n;

    ovs_mutex_lock(&dp_netdev_mutex);

    while (argc > 1) {
        if (!strcmp(argv[1], "-pmd") && argc > 2) {
            if (str_to_uint(argv[2], 10, &core_id)) {
                filter_on_pmd = true;
            }
            argc -= 2;
            argv += 2;
        } else {
            dp = shash_find_data(&dp_netdevs, argv[1]);
            argc -= 1;
            argv += 1;
        }
    }

    if (!dp) {
        if (shash_count(&dp_netdevs) == 1) {
            /* There's only one datapath */
            dp = shash_first(&dp_netdevs)->data;
        } else {
            ovs_mutex_unlock(&dp_netdev_mutex);
            unixctl_command_reply_error(conn,
                                        "please specify an existing datapath");
            return;
        }
    }

    sorted_poll_thread_list(dp, &pmd_list, &n);
    for (size_t i = 0; i < n; i++) {
        struct dp_netdev_pmd_thread *pmd = pmd_list[i];
        if (!pmd) {
            break;
        }
        if (filter_on_pmd && pmd->core_id != core_id) {
            continue;
        }
        if (type == PMD_INFO_SHOW_RXQ) {
            pmd_info_show_rxq(&reply, pmd);
        } else if (type == PMD_INFO_CLEAR_STATS) {
            pmd_perf_stats_clear(&pmd->perf_stats);
        } else if (type == PMD_INFO_SHOW_STATS) {
            pmd_info_show_stats(&reply, pmd);
        } else if (type == PMD_INFO_PERF_SHOW) {
            pmd_info_show_perf(&reply, pmd, (struct pmd_perf_params *)aux);
        }
    }
    free(pmd_list);

    ovs_mutex_unlock(&dp_netdev_mutex);

    unixctl_command_reply(conn, ds_cstr(&reply));
    ds_destroy(&reply);
}

static void
pmd_perf_show_cmd(struct unixctl_conn *conn, int argc,
                          const char *argv[],
                          void *aux OVS_UNUSED)
{
    struct pmd_perf_params par;
    long int it_hist = 0, ms_hist = 0;
    par.histograms = true;

    while (argc > 1) {
        if (!strcmp(argv[1], "-nh")) {
            par.histograms = false;
            argc -= 1;
            argv += 1;
        } else if (!strcmp(argv[1], "-it") && argc > 2) {
            it_hist = strtol(argv[2], NULL, 10);
            if (it_hist < 0) {
                it_hist = 0;
            } else if (it_hist > HISTORY_LEN) {
                it_hist = HISTORY_LEN;
            }
            argc -= 2;
            argv += 2;
        } else if (!strcmp(argv[1], "-ms") && argc > 2) {
            ms_hist = strtol(argv[2], NULL, 10);
            if (ms_hist < 0) {
                ms_hist = 0;
            } else if (ms_hist > HISTORY_LEN) {
                ms_hist = HISTORY_LEN;
            }
            argc -= 2;
            argv += 2;
        } else {
            break;
        }
    }
    par.iter_hist_len = it_hist;
    par.ms_hist_len = ms_hist;
    par.command_type = PMD_INFO_PERF_SHOW;
    dpif_netdev_pmd_info(conn, argc, argv, &par);
}

static int
dpif_netdev_init(void)//command注册
{
    static enum pmd_info_type show_aux = PMD_INFO_SHOW_STATS,
                              clear_aux = PMD_INFO_CLEAR_STATS,
                              poll_aux = PMD_INFO_SHOW_RXQ;

    unixctl_command_register("dpif-netdev/pmd-stats-show", "[-pmd core] [dp]",
                             0, 3, dpif_netdev_pmd_info,
                             (void *)&show_aux);
    unixctl_command_register("dpif-netdev/pmd-stats-clear", "[-pmd core] [dp]",
                             0, 3, dpif_netdev_pmd_info,
                             (void *)&clear_aux);
    unixctl_command_register("dpif-netdev/pmd-rxq-show", "[-pmd core] [dp]",
                             0, 3, dpif_netdev_pmd_info,
                             (void *)&poll_aux);
    unixctl_command_register("dpif-netdev/pmd-perf-show",
                             "[-nh] [-it iter-history-len]"
                             " [-ms ms-history-len]"
                             " [-pmd core] [dp]",
                             0, 8, pmd_perf_show_cmd,
                             NULL);
    unixctl_command_register("dpif-netdev/pmd-rxq-rebalance", "[dp]",
                             0, 1, dpif_netdev_pmd_rebalance,
                             NULL);
    unixctl_command_register("dpif-netdev/pmd-perf-log-set",
                             "on|off [-b before] [-a after] [-e|-ne] "
                             "[-us usec] [-q qlen]",
                             0, 10, pmd_perf_log_set_cmd,
                             NULL);
    return 0;
}

static int
dpif_netdev_enumerate(struct sset *all_dps,
                      const struct dpif_class *dpif_class)
{
    struct shash_node *node;

    ovs_mutex_lock(&dp_netdev_mutex);
    SHASH_FOR_EACH(node, &dp_netdevs) {
        struct dp_netdev *dp = node->data;
        if (dpif_class != dp->class) {
            /* 'dp_netdevs' contains both "netdev" and "dummy" dpifs.
             * If the class doesn't match, skip this dpif. */
             continue;
        }
        sset_add(all_dps, node->name);
    }
    ovs_mutex_unlock(&dp_netdev_mutex);

    return 0;
}

static bool
dpif_netdev_class_is_dummy(const struct dpif_class *class)
{
    return class != &dpif_netdev_class;
}

//针对netdev类型port，对于internal类型，打开时，会打开为tap口
static const char *
dpif_netdev_port_open_type(const struct dpif_class *class, const char *type)
{
    return strcmp(type, "internal") ? type
                  : dpif_netdev_class_is_dummy(class) ? "dummy-internal"
                  : "tap";
}

static struct dpif *
create_dpif_netdev(struct dp_netdev *dp)
{
    uint16_t netflow_id = hash_string(dp->name, 0);
    struct dpif_netdev *dpif;

    ovs_refcount_ref(&dp->ref_cnt);

    dpif = xmalloc(sizeof *dpif);
    dpif_init(&dpif->dpif, dp->class, dp->name, netflow_id >> 8, netflow_id);
    dpif->dp = dp;
    dpif->last_port_seq = seq_read(dp->port_seq);

    return &dpif->dpif;
}

/* Choose an unused, non-zero port number and return it on success.
 * Return ODPP_NONE on failure. */
//port-id号分配
static odp_port_t
choose_port(struct dp_netdev *dp, const char *name)//为port分配一个id号
    OVS_REQUIRES(dp->port_mutex)
{
    uint32_t port_no;

    if (dp->class != &dpif_netdev_class) {
        const char *p;
        int start_no = 0;

        /* If the port name begins with "br", start the number search at
         * 100 to make writing tests easier. */
        if (!strncmp(name, "br", 2)) {
            start_no = 100;
        }

        /* If the port name contains a number, try to assign that port number.
         * This can make writing unit tests easier because port numbers are
         * predictable. */
        for (p = name; *p != '\0'; p++) {
            if (isdigit((unsigned char) *p)) {
                port_no = start_no + strtol(p, NULL, 10);
                if (port_no > 0 && port_no != odp_to_u32(ODPP_NONE)
                    && !dp_netdev_lookup_port(dp, u32_to_odp(port_no))) {
                    return u32_to_odp(port_no);
                }
                break;
            }
        }
    }

    //找一个未用到的port-number
    for (port_no = 1; port_no <= UINT16_MAX; port_no++) {
        if (!dp_netdev_lookup_port(dp, u32_to_odp(port_no))) {
            return u32_to_odp(port_no);
        }
    }

    return ODPP_NONE;
}

//datapath netdev基类创建，设置基本信息
static int
create_dp_netdev(const char *name, const struct dpif_class *class,
                 struct dp_netdev **dpp)
    OVS_REQUIRES(dp_netdev_mutex)
{
    static struct ovsthread_once tsc_freq_check = OVSTHREAD_ONCE_INITIALIZER;
    struct dp_netdev *dp;
    int error;

    /* Avoid estimating TSC frequency for dummy datapath to not slow down
     * unit tests. */
    if (!dpif_netdev_class_is_dummy(class)
        && ovsthread_once_start(&tsc_freq_check)) {
        pmd_perf_estimate_tsc_frequency();
        ovsthread_once_done(&tsc_freq_check);
    }

    dp = xzalloc(sizeof *dp);
    //将创建的dp加入到dp_netdevs链上，由netdev负责的所有dp均在此链上。
    shash_add(&dp_netdevs, name, dp);
    *CONST_CAST(const struct dpif_class **, &dp->class) = class;
    *CONST_CAST(const char **, &dp->name) = xstrdup(name);
    ovs_refcount_init(&dp->ref_cnt);
    atomic_flag_clear(&dp->destroyed);

    ovs_mutex_init(&dp->port_mutex);
    hmap_init(&dp->ports);
    dp->port_seq = seq_create();
    fat_rwlock_init(&dp->upcall_rwlock);

    dp->reconfigure_seq = seq_create();
    dp->last_reconfigure_seq = seq_read(dp->reconfigure_seq);

    for (int i = 0; i < N_METER_LOCKS; ++i) {
        ovs_mutex_init_adaptive(&dp->meter_locks[i]);
    }

    /* Disable upcalls by default. */
    //禁止upcall
    dp_netdev_disable_upcall(dp);
    dp->upcall_aux = NULL;
    dp->upcall_cb = NULL;

    dp->conntrack = conntrack_init();//连接跟踪初始化

    atomic_init(&dp->emc_insert_min, DEFAULT_EM_FLOW_INSERT_MIN);
    atomic_init(&dp->tx_flush_interval, DEFAULT_TX_FLUSH_INTERVAL);

    cmap_init(&dp->poll_threads);
    dp->pmd_rxq_assign_cyc = true;

    ovs_mutex_init(&dp->tx_qid_pool_mutex);
    /* We need 1 Tx queue for each possible core + 1 for non-PMD threads. */
    dp->tx_qid_pool = id_pool_create(0, ovs_numa_get_n_cores() + 1);

    ovs_mutex_init_recursive(&dp->non_pmd_mutex);
    ovsthread_key_create(&dp->per_pmd_key, NULL);

    ovs_mutex_lock(&dp->port_mutex);
    /* non-PMD will be created before all other threads and will
     * allocate static_tx_qid = 0. */
    dp_netdev_set_nonpmd(dp);

    //创建一个datapath时，会隐含创建一个"internal“类型的port
    //这个port的名称与datapath的名称相同，且端口号为０
    error = do_add_port(dp, name, dpif_netdev_port_open_type(dp->class,
                                                             "internal"),
                        ODPP_LOCAL);
    ovs_mutex_unlock(&dp->port_mutex);
    if (error) {
        dp_netdev_free(dp);
        return error;
    }

    dp->last_tnl_conf_seq = seq_read(tnl_conf_seq);
    *dpp = dp;
    return 0;
}

static void
dp_netdev_request_reconfigure(struct dp_netdev *dp)
{
    seq_change(dp->reconfigure_seq);
}

//检查dp_netdev是否需要重配置
static bool
dp_netdev_is_reconf_required(struct dp_netdev *dp)
{
    return seq_read(dp->reconfigure_seq) != dp->last_reconfigure_seq;
}

//dp层面打开一个网络设备
static int
dpif_netdev_open(const struct dpif_class *class, const char *name,
                 bool create, struct dpif **dpifp)
{
    struct dp_netdev *dp;
    int error;

    ovs_mutex_lock(&dp_netdev_mutex);
    dp = shash_find_data(&dp_netdevs, name);
    //检查此dev是否已创建
    if (!dp) {
    	//创建dp_netdev
        error = create ? create_dp_netdev(name, class, &dp) : ENODEV;//创建
    } else {
        error = (dp->class != class ? EINVAL
                 : create ? EEXIST
                 : 0);//如果是创建，则返回已创建
    }
    if (!error) {
    	//创建dpif_netdev
        *dpifp = create_dpif_netdev(dp);
        dp->dpif = *dpifp;
    }
    ovs_mutex_unlock(&dp_netdev_mutex);

    return error;
}

static void
dp_netdev_destroy_upcall_lock(struct dp_netdev *dp)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    /* Check that upcalls are disabled, i.e. that the rwlock is taken */
    ovs_assert(fat_rwlock_tryrdlock(&dp->upcall_rwlock));

    /* Before freeing a lock we should release it */
    fat_rwlock_unlock(&dp->upcall_rwlock);
    fat_rwlock_destroy(&dp->upcall_rwlock);
}

static void
dp_delete_meter(struct dp_netdev *dp, uint32_t meter_id)
    OVS_REQUIRES(dp->meter_locks[meter_id % N_METER_LOCKS])
{
    if (dp->meters[meter_id]) {
        free(dp->meters[meter_id]);
        dp->meters[meter_id] = NULL;
    }
}

/* Requires dp_netdev_mutex so that we can't get a new reference to 'dp'
 * through the 'dp_netdevs' shash while freeing 'dp'. */
static void
dp_netdev_free(struct dp_netdev *dp)
    OVS_REQUIRES(dp_netdev_mutex)
{
    struct dp_netdev_port *port, *next;

    shash_find_and_delete(&dp_netdevs, dp->name);

    ovs_mutex_lock(&dp->port_mutex);
    HMAP_FOR_EACH_SAFE (port, next, node, &dp->ports) {
        do_del_port(dp, port);
    }
    ovs_mutex_unlock(&dp->port_mutex);

    dp_netdev_destroy_all_pmds(dp, true);
    cmap_destroy(&dp->poll_threads);

    ovs_mutex_destroy(&dp->tx_qid_pool_mutex);
    id_pool_destroy(dp->tx_qid_pool);

    ovs_mutex_destroy(&dp->non_pmd_mutex);
    ovsthread_key_delete(dp->per_pmd_key);

    conntrack_destroy(dp->conntrack);


    seq_destroy(dp->reconfigure_seq);

    seq_destroy(dp->port_seq);
    hmap_destroy(&dp->ports);
    ovs_mutex_destroy(&dp->port_mutex);

    /* Upcalls must be disabled at this point */
    dp_netdev_destroy_upcall_lock(dp);

    int i;

    for (i = 0; i < MAX_METERS; ++i) {
        meter_lock(dp, i);
        dp_delete_meter(dp, i);
        meter_unlock(dp, i);
    }
    for (i = 0; i < N_METER_LOCKS; ++i) {
        ovs_mutex_destroy(&dp->meter_locks[i]);
    }

    free(dp->pmd_cmask);
    free(CONST_CAST(char *, dp->name));
    free(dp);
}

static void
dp_netdev_unref(struct dp_netdev *dp)
{
    if (dp) {
        /* Take dp_netdev_mutex so that, if dp->ref_cnt falls to zero, we can't
         * get a new reference to 'dp' through the 'dp_netdevs' shash. */
        ovs_mutex_lock(&dp_netdev_mutex);
        if (ovs_refcount_unref_relaxed(&dp->ref_cnt) == 1) {
            dp_netdev_free(dp);
        }
        ovs_mutex_unlock(&dp_netdev_mutex);
    }
}

static void
dpif_netdev_close(struct dpif *dpif)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);

    dp_netdev_unref(dp);
    free(dpif);
}

//datapath删除
static int
dpif_netdev_destroy(struct dpif *dpif)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);

    if (!atomic_flag_test_and_set(&dp->destroyed)) {//廷后删除
        if (ovs_refcount_unref_relaxed(&dp->ref_cnt) == 1) {
            /* Can't happen: 'dpif' still owns a reference to 'dp'. */
            OVS_NOT_REACHED();
        }
    }

    return 0;
}

/* Add 'n' to the atomic variable 'var' non-atomically and using relaxed
 * load/store semantics.  While the increment is not atomic, the load and
 * store operations are, making it impossible to read inconsistent values.
 *
 * This is used to update thread local stats counters. */
static void
non_atomic_ullong_add(atomic_ullong *var, unsigned long long n)
{
    unsigned long long tmp;

    atomic_read_relaxed(var, &tmp);
    tmp += n;
    atomic_store_relaxed(var, tmp);
}

static int
dpif_netdev_get_stats(const struct dpif *dpif, struct dpif_dp_stats *stats)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_pmd_thread *pmd;
    uint64_t pmd_stats[PMD_N_STATS];

    stats->n_flows = stats->n_hit = stats->n_missed = stats->n_lost = 0;
    CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
        stats->n_flows += cmap_count(&pmd->flow_table);
        pmd_perf_read_counters(&pmd->perf_stats, pmd_stats);
        stats->n_hit += pmd_stats[PMD_STAT_EXACT_HIT];
        stats->n_hit += pmd_stats[PMD_STAT_SMC_HIT];
        stats->n_hit += pmd_stats[PMD_STAT_MASKED_HIT];
        stats->n_missed += pmd_stats[PMD_STAT_MISS];
        stats->n_lost += pmd_stats[PMD_STAT_LOST];
    }
    stats->n_masks = UINT32_MAX;
    stats->n_mask_hit = UINT64_MAX;

    return 0;
}

static void
dp_netdev_reload_pmd__(struct dp_netdev_pmd_thread *pmd)
{
    if (pmd->core_id == NON_PMD_CORE_ID) {
        ovs_mutex_lock(&pmd->dp->non_pmd_mutex);
        ovs_mutex_lock(&pmd->port_mutex);
        pmd_load_cached_ports(pmd);
        ovs_mutex_unlock(&pmd->port_mutex);
        ovs_mutex_unlock(&pmd->dp->non_pmd_mutex);
        return;
    }

    seq_change(pmd->reload_seq);
    //知会pmd线程进行处理（pmd在维护工作时，会检查此变量）
    atomic_store_explicit(&pmd->reload, true, memory_order_release);
}

static uint32_t
hash_port_no(odp_port_t port_no)
{
    return hash_int(odp_to_u32(port_no), 0);
}

//创建port
static int
port_create(const char *devname, const char *type,
            odp_port_t port_no, struct dp_netdev_port **portp)
{
    struct netdev_saved_flags *sf;
    struct dp_netdev_port *port;
    enum netdev_flags flags;
    struct netdev *netdev;
    int error;

    *portp = NULL;

    /* Open and validate network device. */
    //构造netdev
    error = netdev_open(devname, type, &netdev);
    if (error) {
        return error;
    }
    /* XXX reject non-Ethernet devices */

    //获取其状态
    netdev_get_flags(netdev, &flags);
    if (flags & NETDEV_LOOPBACK) {
        VLOG_ERR("%s: cannot add a loopback device", devname);
        error = EINVAL;
        goto out;
    }

    //将其设置为混杂模式
    error = netdev_turn_flags_on(netdev, NETDEV_PROMISC, &sf);
    if (error) {
        VLOG_ERR("%s: cannot set promisc flag", devname);
        goto out;
    }

    port = xzalloc(sizeof *port);
    port->port_no = port_no;
    port->netdev = netdev;
    port->type = xstrdup(type);
    port->sf = sf;//保存的flags
    port->emc_enabled = true;
    port->need_reconfigure = true;
    ovs_mutex_init(&port->txq_used_mutex);

    *portp = port;

    return 0;

out:
    netdev_close(netdev);
    return error;
}

//创建指定类型的port,指定port_no为port编号，devname为port名称
static int
do_add_port(struct dp_netdev *dp, const char *devname, const char *type,
            odp_port_t port_no)
    OVS_REQUIRES(dp->port_mutex)
{
    struct dp_netdev_port *port;
    int error;

    /* Reject devices already in 'dp'. */
    if (!get_port_by_name(dp, devname, &port)) {
    	//确保port在datapath中不存在
        return EEXIST;
    }

    //创建接口（及其队列，配置dev）
    error = port_create(devname, type, port_no, &port);
    if (error) {
        return error;
    }

    hmap_insert(&dp->ports, &port->node, hash_port_no(port_no));
    seq_change(dp->port_seq);

    //datapath重新配置
    reconfigure_datapath(dp);

    /* Check that port was successfully configured. */
    return dp_netdev_lookup_port(dp, port_no) ? 0 : EINVAL;
}

static int
dpif_netdev_port_add(struct dpif *dpif, struct netdev *netdev,
                     odp_port_t *port_nop)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    char namebuf[NETDEV_VPORT_NAME_BUFSIZE];
    const char *dpif_port;
    odp_port_t port_no;
    int error;

    ovs_mutex_lock(&dp->port_mutex);
    dpif_port = netdev_vport_get_dpif_port(netdev, namebuf, sizeof namebuf);
    if (*port_nop != ODPP_NONE) {
    	//已存在
        port_no = *port_nop;
        error = dp_netdev_lookup_port(dp, *port_nop) ? EBUSY : 0;
    } else {
        port_no = choose_port(dp, dpif_port);
        error = port_no == ODPP_NONE ? EFBIG : 0;
    }
    if (!error) {
        *port_nop = port_no;
        error = do_add_port(dp, dpif_port, netdev_get_type(netdev), port_no);
    }
    ovs_mutex_unlock(&dp->port_mutex);

    return error;
}

static int
dpif_netdev_port_del(struct dpif *dpif, odp_port_t port_no)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    int error;

    ovs_mutex_lock(&dp->port_mutex);
    if (port_no == ODPP_LOCAL) {//如果是local口，返回无效参数
        error = EINVAL;
    } else {//否则移除此port
        struct dp_netdev_port *port;

        error = get_port_by_number(dp, port_no, &port);
        if (!error) {
            do_del_port(dp, port);
        }
    }
    ovs_mutex_unlock(&dp->port_mutex);

    return error;
}

static bool
is_valid_port_number(odp_port_t port_no)
{
    return port_no != ODPP_NONE;
}

static struct dp_netdev_port *
dp_netdev_lookup_port(const struct dp_netdev *dp, odp_port_t port_no)//通过port_no在dp_netdev中找对应port
    OVS_REQUIRES(dp->port_mutex)
{
    struct dp_netdev_port *port;

    HMAP_FOR_EACH_WITH_HASH (port, node, hash_port_no(port_no), &dp->ports) {
        if (port->port_no == port_no) {
            return port;
        }
    }
    return NULL;
}

static int
get_port_by_number(struct dp_netdev *dp,
                   odp_port_t port_no, struct dp_netdev_port **portp)
    OVS_REQUIRES(dp->port_mutex)
{
    if (!is_valid_port_number(port_no)) {
        *portp = NULL;
        return EINVAL;
    } else {
        *portp = dp_netdev_lookup_port(dp, port_no);
        return *portp ? 0 : ENODEV;
    }
}

static void
port_destroy(struct dp_netdev_port *port)
{
    if (!port) {
        return;
    }

    netdev_close(port->netdev);
    netdev_restore_flags(port->sf);

    for (unsigned i = 0; i < port->n_rxq; i++) {
        netdev_rxq_close(port->rxqs[i].rx);
    }
    ovs_mutex_destroy(&port->txq_used_mutex);
    free(port->rxq_affinity_list);
    free(port->txq_used);
    free(port->rxqs);
    free(port->type);
    free(port);
}

//通过名称查找dp_netdev
static int
get_port_by_name(struct dp_netdev *dp,
                 const char *devname, struct dp_netdev_port **portp)
    OVS_REQUIRES(dp->port_mutex)
{
    struct dp_netdev_port *port;

    HMAP_FOR_EACH (port, node, &dp->ports) {
        if (!strcmp(netdev_get_name(port->netdev), devname)) {//名称和devname相同
            *portp = port;
            return 0;
        }
    }

    /* Callers of dpif_netdev_port_query_by_name() expect ENODEV for a non
     * existing port. */
    return ENODEV;
}

/* Returns 'true' if there is a port with pmd netdev. */
//检查dp中是否含有pmd设备
static bool
has_pmd_port(struct dp_netdev *dp)
    OVS_REQUIRES(dp->port_mutex)
{
    struct dp_netdev_port *port;

    HMAP_FOR_EACH (port, node, &dp->ports) {
        if (netdev_is_pmd(port->netdev)) {
            return true;
        }
    }

    return false;
}

static void
do_del_port(struct dp_netdev *dp, struct dp_netdev_port *port)
    OVS_REQUIRES(dp->port_mutex)
{
    hmap_remove(&dp->ports, &port->node);
    seq_change(dp->port_seq);

    reconfigure_datapath(dp);

    port_destroy(port);
}

static void
answer_port_query(const struct dp_netdev_port *port,
                  struct dpif_port *dpif_port)//将port封装为dpif_port(结构体间转换）
{
    dpif_port->name = xstrdup(netdev_get_name(port->netdev));
    dpif_port->type = xstrdup(port->type);
    dpif_port->port_no = port->port_no;
}

static int
dpif_netdev_port_query_by_number(const struct dpif *dpif, odp_port_t port_no,
                                 struct dpif_port *dpif_port)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_port *port;
    int error;

    ovs_mutex_lock(&dp->port_mutex);
    error = get_port_by_number(dp, port_no, &port);
    if (!error && dpif_port) {
        answer_port_query(port, dpif_port);
    }
    ovs_mutex_unlock(&dp->port_mutex);

    return error;
}

//在dpif下查找对应的devname,并返回其对应的dpif-port信息
static int
dpif_netdev_port_query_by_name(const struct dpif *dpif, const char *devname,
                               struct dpif_port *dpif_port)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_port *port;
    int error;

    ovs_mutex_lock(&dp->port_mutex);
    error = get_port_by_name(dp, devname, &port);
    if (!error && dpif_port) {
        answer_port_query(port, dpif_port);
    }
    ovs_mutex_unlock(&dp->port_mutex);

    return error;
}

static void
dp_netdev_flow_free(struct dp_netdev_flow *flow)
{
    dp_netdev_actions_free(dp_netdev_flow_get_actions(flow));
    free(flow);
}

static void dp_netdev_flow_unref(struct dp_netdev_flow *flow)
{
    if (ovs_refcount_unref_relaxed(&flow->ref_cnt) == 1) {
    	//延迟释放
        ovsrcu_postpone(dp_netdev_flow_free, flow);
    }
}

static uint32_t
dp_netdev_flow_hash(const ovs_u128 *ufid)
{
    return ufid->u32[0];
}

//通过pmd->classifiers表查找in_port的dpcls,实现入接口分类
static inline struct dpcls *
dp_netdev_pmd_lookup_dpcls(struct dp_netdev_pmd_thread *pmd,
                           odp_port_t in_port)
{
    struct dpcls *cls;
    uint32_t hash = hash_port_no(in_port);
    CMAP_FOR_EACH_WITH_HASH (cls, node, hash, &pmd->classifiers) {
        if (cls->in_port == in_port) {
            /* Port classifier exists already */
            return cls;
        }
    }
    return NULL;
}

//通过in_port检查分类器，如果没有找到创建一个
static inline struct dpcls *
dp_netdev_pmd_find_dpcls(struct dp_netdev_pmd_thread *pmd,
                         odp_port_t in_port)
    OVS_REQUIRES(pmd->flow_mutex)
{
    struct dpcls *cls = dp_netdev_pmd_lookup_dpcls(pmd, in_port);
    uint32_t hash = hash_port_no(in_port);

    if (!cls) {
        /* Create new classifier for in_port */
        cls = xmalloc(sizeof(*cls));
        dpcls_init(cls);
        cls->in_port = in_port;
        cmap_insert(&pmd->classifiers, &cls->node, hash);
        VLOG_DBG("Creating dpcls %p for in_port %d", cls, in_port);
    }
    return cls;
}

#define MAX_FLOW_MARK       (UINT32_MAX - 1)
#define INVALID_FLOW_MARK   (UINT32_MAX)

struct megaflow_to_mark_data {
    const struct cmap_node node;
    ovs_u128 mega_ufid;
    uint32_t mark;
};

struct flow_mark {
    struct cmap megaflow_to_mark;
    struct cmap mark_to_flow;
    struct id_pool *pool;
};

static struct flow_mark flow_mark = {
    .megaflow_to_mark = CMAP_INITIALIZER,
    .mark_to_flow = CMAP_INITIALIZER,
};

static uint32_t
flow_mark_alloc(void)
{
    uint32_t mark;

    if (!flow_mark.pool) {
        /* Haven't initiated yet, do it here */
        flow_mark.pool = id_pool_create(0, MAX_FLOW_MARK);
    }

    if (id_pool_alloc_id(flow_mark.pool, &mark)) {
        return mark;
    }

    return INVALID_FLOW_MARK;
}

static void
flow_mark_free(uint32_t mark)
{
    id_pool_free_id(flow_mark.pool, mark);
}

/* associate megaflow with a mark, which is a 1:1 mapping */
static void
megaflow_to_mark_associate(const ovs_u128 *mega_ufid, uint32_t mark)
{
    size_t hash = dp_netdev_flow_hash(mega_ufid);
    struct megaflow_to_mark_data *data = xzalloc(sizeof(*data));

    data->mega_ufid = *mega_ufid;
    data->mark = mark;

    cmap_insert(&flow_mark.megaflow_to_mark,
                CONST_CAST(struct cmap_node *, &data->node), hash);
}

/* disassociate meagaflow with a mark */
static void
megaflow_to_mark_disassociate(const ovs_u128 *mega_ufid)
{
    size_t hash = dp_netdev_flow_hash(mega_ufid);
    struct megaflow_to_mark_data *data;

    CMAP_FOR_EACH_WITH_HASH (data, node, hash, &flow_mark.megaflow_to_mark) {
        if (ovs_u128_equals(*mega_ufid, data->mega_ufid)) {
            cmap_remove(&flow_mark.megaflow_to_mark,
                        CONST_CAST(struct cmap_node *, &data->node), hash);
            ovsrcu_postpone(free, data);
            return;
        }
    }

    VLOG_WARN("Masked ufid "UUID_FMT" is not associated with a mark?\n",
              UUID_ARGS((struct uuid *)mega_ufid));
}

static inline uint32_t
megaflow_to_mark_find(const ovs_u128 *mega_ufid)
{
    size_t hash = dp_netdev_flow_hash(mega_ufid);
    struct megaflow_to_mark_data *data;

    CMAP_FOR_EACH_WITH_HASH (data, node, hash, &flow_mark.megaflow_to_mark) {
        if (ovs_u128_equals(*mega_ufid, data->mega_ufid)) {
            return data->mark;
        }
    }

    VLOG_DBG("Mark id for ufid "UUID_FMT" was not found\n",
             UUID_ARGS((struct uuid *)mega_ufid));
    return INVALID_FLOW_MARK;
}

/* associate mark with a flow, which is 1:N mapping */
static void
mark_to_flow_associate(const uint32_t mark, struct dp_netdev_flow *flow)
{
    dp_netdev_flow_ref(flow);

    cmap_insert(&flow_mark.mark_to_flow,
                CONST_CAST(struct cmap_node *, &flow->mark_node),
                hash_int(mark, 0));
    flow->mark = mark;

    VLOG_DBG("Associated dp_netdev flow %p with mark %u\n", flow, mark);
}

static bool
flow_mark_has_no_ref(uint32_t mark)
{
    struct dp_netdev_flow *flow;

    CMAP_FOR_EACH_WITH_HASH (flow, mark_node, hash_int(mark, 0),
                             &flow_mark.mark_to_flow) {
        if (flow->mark == mark) {
            return false;
        }
    }

    return true;
}

static int
mark_to_flow_disassociate(struct dp_netdev_pmd_thread *pmd,
                          struct dp_netdev_flow *flow)
{
    int ret = 0;
    uint32_t mark = flow->mark;
    struct cmap_node *mark_node = CONST_CAST(struct cmap_node *,
                                             &flow->mark_node);

    cmap_remove(&flow_mark.mark_to_flow, mark_node, hash_int(mark, 0));
    flow->mark = INVALID_FLOW_MARK;

    /*
     * no flow is referencing the mark any more? If so, let's
     * remove the flow from hardware and free the mark.
     */
    if (flow_mark_has_no_ref(mark)) {
        struct dp_netdev_port *port;
        odp_port_t in_port = flow->flow.in_port.odp_port;

        ovs_mutex_lock(&pmd->dp->port_mutex);
        port = dp_netdev_lookup_port(pmd->dp, in_port);
        if (port) {
            ret = netdev_flow_del(port->netdev, &flow->mega_ufid, NULL);
        }
        ovs_mutex_unlock(&pmd->dp->port_mutex);

        flow_mark_free(mark);
        VLOG_DBG("Freed flow mark %u\n", mark);

        megaflow_to_mark_disassociate(&flow->mega_ufid);
    }
    dp_netdev_flow_unref(flow);

    return ret;
}

static void
flow_mark_flush(struct dp_netdev_pmd_thread *pmd)
{
    struct dp_netdev_flow *flow;

    CMAP_FOR_EACH (flow, mark_node, &flow_mark.mark_to_flow) {
        if (flow->pmd_id == pmd->core_id) {
            queue_netdev_flow_del(pmd, flow);
        }
    }
}

static struct dp_netdev_flow *
mark_to_flow_find(const struct dp_netdev_pmd_thread *pmd,
                  const uint32_t mark)
{
    struct dp_netdev_flow *flow;

    CMAP_FOR_EACH_WITH_HASH (flow, mark_node, hash_int(mark, 0),
                             &flow_mark.mark_to_flow) {
        if (flow->mark == mark && flow->pmd_id == pmd->core_id &&
            flow->dead == false) {
            return flow;
        }
    }

    return NULL;
}

static struct dp_flow_offload_item *
dp_netdev_alloc_flow_offload(struct dp_netdev_pmd_thread *pmd,
                             struct dp_netdev_flow *flow,
                             int op)
{
    struct dp_flow_offload_item *offload;

    offload = xzalloc(sizeof(*offload));
    offload->pmd = pmd;
    offload->flow = flow;
    offload->op = op;

    dp_netdev_flow_ref(flow);
    dp_netdev_pmd_try_ref(pmd);

    return offload;
}

static void
dp_netdev_free_flow_offload(struct dp_flow_offload_item *offload)
{
    dp_netdev_pmd_unref(offload->pmd);
    dp_netdev_flow_unref(offload->flow);

    free(offload->actions);
    free(offload);
}

//添加需要offload的流量
static void
dp_netdev_append_flow_offload(struct dp_flow_offload_item *offload)
{
    ovs_mutex_lock(&dp_flow_offload.mutex);
    ovs_list_push_back(&dp_flow_offload.list, &offload->node);
    //发送信号，知会下发线程处理flow offload
    xpthread_cond_signal(&dp_flow_offload.cond);
    ovs_mutex_unlock(&dp_flow_offload.mutex);
}

static int
dp_netdev_flow_offload_del(struct dp_flow_offload_item *offload)
{
    return mark_to_flow_disassociate(offload->pmd, offload->flow);
}

/*
 * There are two flow offload operations here: addition and modification.
 *
 * For flow addition, this function does:
 * - allocate a new flow mark id
 * - perform hardware flow offload
 * - associate the flow mark with flow and mega flow
 *
 * For flow modification, both flow mark and the associations are still
 * valid, thus only item 2 needed.
 */
static int
dp_netdev_flow_offload_put(struct dp_flow_offload_item *offload)
{
    struct dp_netdev_port *port;
    struct dp_netdev_pmd_thread *pmd = offload->pmd;
    struct dp_netdev_flow *flow = offload->flow;
    odp_port_t in_port = flow->flow.in_port.odp_port;
    bool modification = offload->op == DP_NETDEV_FLOW_OFFLOAD_OP_MOD;
    struct offload_info info;
    uint32_t mark;
    int ret;

    if (flow->dead) {
        return -1;
    }

    if (modification) {
        mark = flow->mark;
        ovs_assert(mark != INVALID_FLOW_MARK);
    } else {
        /*
         * If a mega flow has already been offloaded (from other PMD
         * instances), do not offload it again.
         */
        mark = megaflow_to_mark_find(&flow->mega_ufid);
        if (mark != INVALID_FLOW_MARK) {
            VLOG_DBG("Flow has already been offloaded with mark %u\n", mark);
            if (flow->mark != INVALID_FLOW_MARK) {
                ovs_assert(flow->mark == mark);
            } else {
                mark_to_flow_associate(mark, flow);
            }
            return 0;
        }

        mark = flow_mark_alloc();
        if (mark == INVALID_FLOW_MARK) {
            VLOG_ERR("Failed to allocate flow mark!\n");
        }
    }
    info.flow_mark = mark;

    ovs_mutex_lock(&pmd->dp->port_mutex);
    port = dp_netdev_lookup_port(pmd->dp, in_port);
    if (!port || netdev_vport_is_vport_class(port->netdev->netdev_class)) {
        ovs_mutex_unlock(&pmd->dp->port_mutex);
        goto err_free;
    }
    ret = netdev_flow_put(port->netdev, &offload->match,
                          CONST_CAST(struct nlattr *, offload->actions),
                          offload->actions_len, &flow->mega_ufid, &info,
                          NULL);
    ovs_mutex_unlock(&pmd->dp->port_mutex);

    if (ret) {
        goto err_free;
    }

    if (!modification) {
        megaflow_to_mark_associate(&flow->mega_ufid, mark);
        mark_to_flow_associate(mark, flow);
    }
    return 0;

err_free:
    if (!modification) {
        flow_mark_free(mark);
    } else {
        mark_to_flow_disassociate(pmd, flow);
    }
    return -1;
}

static void *
dp_netdev_flow_offload_main(void *data OVS_UNUSED)
{
    struct dp_flow_offload_item *offload;
    struct ovs_list *list;
    const char *op;
    int ret;

    for (;;) {
        ovs_mutex_lock(&dp_flow_offload.mutex);
        if (ovs_list_is_empty(&dp_flow_offload.list)) {
        	//如果队列为空，则等待信号
            ovsrcu_quiesce_start();
            ovs_mutex_cond_wait(&dp_flow_offload.cond,
                                &dp_flow_offload.mutex);
            ovsrcu_quiesce_end();
        }
        //取出需要offload的流，按op执行添加删除修改
        list = ovs_list_pop_front(&dp_flow_offload.list);
        offload = CONTAINER_OF(list, struct dp_flow_offload_item, node);
        ovs_mutex_unlock(&dp_flow_offload.mutex);

        switch (offload->op) {
        case DP_NETDEV_FLOW_OFFLOAD_OP_ADD:
            op = "add";
            ret = dp_netdev_flow_offload_put(offload);//添加
            break;
        case DP_NETDEV_FLOW_OFFLOAD_OP_MOD:
            op = "modify";
            ret = dp_netdev_flow_offload_put(offload);//修改
            break;
        case DP_NETDEV_FLOW_OFFLOAD_OP_DEL:
            op = "delete";
            ret = dp_netdev_flow_offload_del(offload);//删除
            break;
        default:
            OVS_NOT_REACHED();
        }

        VLOG_DBG("%s to %s netdev flow\n",
                 ret == 0 ? "succeed" : "failed", op);
        dp_netdev_free_flow_offload(offload);
    }

    return NULL;
}

static void
queue_netdev_flow_del(struct dp_netdev_pmd_thread *pmd,
                      struct dp_netdev_flow *flow)
{
    struct dp_flow_offload_item *offload;

    if (ovsthread_once_start(&offload_thread_once)) {
        xpthread_cond_init(&dp_flow_offload.cond, NULL);
        ovs_thread_create("dp_netdev_flow_offload",
                          dp_netdev_flow_offload_main, NULL);
        ovsthread_once_done(&offload_thread_once);
    }

    offload = dp_netdev_alloc_flow_offload(pmd, flow,
                                           DP_NETDEV_FLOW_OFFLOAD_OP_DEL);
    dp_netdev_append_flow_offload(offload);
}

static void
queue_netdev_flow_put(struct dp_netdev_pmd_thread *pmd,
                      struct dp_netdev_flow *flow, struct match *match,
                      const struct nlattr *actions, size_t actions_len)
{
    struct dp_flow_offload_item *offload;
    int op;

    //未开启flow api	，则直接return
    if (!netdev_is_flow_api_enabled()) {
        return;
    }

    //如果offload_thread未创建，则创建对应的offload_thread
    if (ovsthread_once_start(&offload_thread_once)) {
        xpthread_cond_init(&dp_flow_offload.cond, NULL);
        //创建线程，执行流的下发
        ovs_thread_create("dp_netdev_flow_offload",
                          dp_netdev_flow_offload_main, NULL);
        ovsthread_once_done(&offload_thread_once);
    }

    if (flow->mark != INVALID_FLOW_MARK) {
        op = DP_NETDEV_FLOW_OFFLOAD_OP_MOD;
    } else {
        op = DP_NETDEV_FLOW_OFFLOAD_OP_ADD;
    }
    offload = dp_netdev_alloc_flow_offload(pmd, flow, op);
    offload->match = *match;
    offload->actions = xmalloc(actions_len);
    memcpy(offload->actions, actions, actions_len);
    offload->actions_len = actions_len;

    dp_netdev_append_flow_offload(offload);
}

static void
dp_netdev_pmd_remove_flow(struct dp_netdev_pmd_thread *pmd,
                          struct dp_netdev_flow *flow)
    OVS_REQUIRES(pmd->flow_mutex)
{
    struct cmap_node *node = CONST_CAST(struct cmap_node *, &flow->node);
    struct dpcls *cls;
    odp_port_t in_port = flow->flow.in_port.odp_port;

    cls = dp_netdev_pmd_lookup_dpcls(pmd, in_port);
    ovs_assert(cls != NULL);
    dpcls_remove(cls, &flow->cr);
    cmap_remove(&pmd->flow_table, node, dp_netdev_flow_hash(&flow->ufid));
    if (flow->mark != INVALID_FLOW_MARK) {
        queue_netdev_flow_del(pmd, flow);
    }
    flow->dead = true;

    dp_netdev_flow_unref(flow);
}

static void
dp_netdev_pmd_flow_flush(struct dp_netdev_pmd_thread *pmd)
{
    struct dp_netdev_flow *netdev_flow;

    ovs_mutex_lock(&pmd->flow_mutex);
    CMAP_FOR_EACH (netdev_flow, node, &pmd->flow_table) {
        dp_netdev_pmd_remove_flow(pmd, netdev_flow);
    }
    ovs_mutex_unlock(&pmd->flow_mutex);
}

static int
dpif_netdev_flow_flush(struct dpif *dpif)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_pmd_thread *pmd;

    CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
        dp_netdev_pmd_flow_flush(pmd);
    }

    return 0;
}

struct dp_netdev_port_state {
    struct hmap_position position;
    char *name;
};

static int
dpif_netdev_port_dump_start(const struct dpif *dpif OVS_UNUSED, void **statep)//dump开始时调用
{
    *statep = xzalloc(sizeof(struct dp_netdev_port_state));
    return 0;
}

static int
dpif_netdev_port_dump_next(const struct dpif *dpif, void *state_,
                           struct dpif_port *dpif_port)
{
    struct dp_netdev_port_state *state = state_;
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct hmap_node *node;
    int retval;

    ovs_mutex_lock(&dp->port_mutex);
    node = hmap_at_position(&dp->ports, &state->position);//给定桶索引，给定桶内偏移的方式来遍历hash表
    if (node) {
        struct dp_netdev_port *port;

        port = CONTAINER_OF(node, struct dp_netdev_port, node);

        free(state->name);
        state->name = xstrdup(netdev_get_name(port->netdev));
        dpif_port->name = state->name;
        dpif_port->type = port->type;
        dpif_port->port_no = port->port_no;

        retval = 0;
    } else {
        retval = EOF;
    }
    ovs_mutex_unlock(&dp->port_mutex);

    return retval;
}

static int
dpif_netdev_port_dump_done(const struct dpif *dpif OVS_UNUSED, void *state_)
{
    struct dp_netdev_port_state *state = state_;
    free(state->name);
    free(state);
    return 0;
}

static int
dpif_netdev_port_poll(const struct dpif *dpif_, char **devnamep OVS_UNUSED)
{
    struct dpif_netdev *dpif = dpif_netdev_cast(dpif_);
    uint64_t new_port_seq;
    int error;

    new_port_seq = seq_read(dpif->dp->port_seq);
    if (dpif->last_port_seq != new_port_seq) {
        dpif->last_port_seq = new_port_seq;
        error = ENOBUFS;
    } else {
        error = EAGAIN;
    }

    return error;
}

static void
dpif_netdev_port_poll_wait(const struct dpif *dpif_)
{
    struct dpif_netdev *dpif = dpif_netdev_cast(dpif_);

    seq_wait(dpif->dp->port_seq, dpif->last_port_seq);
}

//将dpcls_rule转为dp_netdev_flow
static struct dp_netdev_flow *
dp_netdev_flow_cast(const struct dpcls_rule *cr)
{
    return cr ? CONTAINER_OF(cr, struct dp_netdev_flow, cr) : NULL;
}

static bool dp_netdev_flow_ref(struct dp_netdev_flow *flow)
{
    return ovs_refcount_try_ref_rcu(&flow->ref_cnt);
}

/* netdev_flow_key utilities.
 *
 * netdev_flow_key is basically a miniflow.  We use these functions
 * (netdev_flow_key_clone, netdev_flow_key_equal, ...) instead of the miniflow
 * functions (miniflow_clone_inline, miniflow_equal, ...), because:
 *
 * - Since we are dealing exclusively with miniflows created by
 *   miniflow_extract(), if the map is different the miniflow is different.
 *   Therefore we can be faster by comparing the map and the miniflow in a
 *   single memcmp().
 * - These functions can be inlined by the compiler. */

/* Given the number of bits set in miniflow's maps, returns the size of the
 * 'netdev_flow_key.mf' */
static inline size_t
netdev_flow_key_size(size_t flow_u64s)
{
    return sizeof(struct miniflow) + MINIFLOW_VALUES_SIZE(flow_u64s);
}

static inline bool
netdev_flow_key_equal(const struct netdev_flow_key *a,
                      const struct netdev_flow_key *b)
{
    /* 'b->len' may be not set yet. */
    return a->hash == b->hash && !memcmp(&a->mf, &b->mf, a->len);
}

/* Used to compare 'netdev_flow_key' in the exact match cache to a miniflow.
 * The maps are compared bitwise, so both 'key->mf' and 'mf' must have been
 * generated by miniflow_extract. */
static inline bool
netdev_flow_key_equal_mf(const struct netdev_flow_key *key,
                         const struct miniflow *mf)
{
    return !memcmp(&key->mf, mf, key->len);//掩码与值需要完全区配
}

static inline void
netdev_flow_key_clone(struct netdev_flow_key *dst,
                      const struct netdev_flow_key *src)
{
    memcpy(dst, src,
           offsetof(struct netdev_flow_key, mf) + src->len);
}

/* Initialize a netdev_flow_key 'mask' from 'match'. */
//依据match中的flow初始化mask,填充miniflow
static inline void
netdev_flow_mask_init(struct netdev_flow_key *mask,
                      const struct match *match)
{
    uint64_t *dst = miniflow_values(&mask->mf);
    struct flowmap fmap;
    uint32_t hash = 0;
    size_t idx;

    /* Only check masks that make sense for the flow. */
    flow_wc_map(&match->flow, &fmap);
    flowmap_init(&mask->mf.map);

    //fmap已被标记为当前flow可能出现的字段map,这里我们遍历这个map
    //返回的idx是当前flow对应的报文中可出现的字段
    FLOWMAP_FOR_EACH_INDEX(idx, fmap) {
        uint64_t mask_u64 = flow_u64_value(&match->wc.masks, idx);

        if (mask_u64) {
        	//在mask中出现了对此字符的限制，设置mask->mf.map
            flowmap_set(&mask->mf.map, idx, 1);
            *dst++ = mask_u64;//填充mask对应的值
            hash = hash_add64(hash, mask_u64);//变更hash值
        }
    }

    map_t map;

    //变更hash值
    FLOWMAP_FOR_EACH_MAP (map, mask->mf.map) {
        hash = hash_add64(hash, map);
    }

    size_t n = dst - miniflow_get_values(&mask->mf);//填充了多少字段

    mask->hash = hash_finish(hash, n * 8);
    mask->len = netdev_flow_key_size(n);//更新有效长度
}

/* Initializes 'dst' as a copy of 'flow' masked with 'mask'. */
//填充dst,使其等于flow ＆ mask之后的结果（如果是严格匹配的话，其值为flow)
static inline void
netdev_flow_key_init_masked(struct netdev_flow_key *dst,
                            const struct flow *flow,
                            const struct netdev_flow_key *mask)
{
    uint64_t *dst_u64 = miniflow_values(&dst->mf);//flow的miniflow起始位置
    const uint64_t *mask_u64 = miniflow_get_values(&mask->mf);//mask的miniflow起始位置
    uint32_t hash = 0;
    uint64_t value;

    dst->len = mask->len;
    dst->mf = mask->mf;   /* Copy maps. */

    //获取对应的值
    FLOW_FOR_EACH_IN_MAPS(value, flow, mask->mf.map) {
        *dst_u64 = value & *mask_u64++;//实现mask与value的与操作，得出结果，将其填充到dst_u64
        hash = hash_add64(hash, *dst_u64++);//更新hash值
    }
    dst->hash = hash_finish(hash,
                            (dst_u64 - miniflow_get_values(&dst->mf)) * 8);//更新hash值
}

static inline bool
emc_entry_alive(struct emc_entry *ce)
{
    return ce->flow && !ce->flow->dead;
}

static void
emc_clear_entry(struct emc_entry *ce)
{
    if (ce->flow) {
        dp_netdev_flow_unref(ce->flow);
        ce->flow = NULL;
    }
}

static inline void
emc_change_entry(struct emc_entry *ce, struct dp_netdev_flow *flow,
                 const struct netdev_flow_key *key)
{
    if (ce->flow != flow) {
        if (ce->flow) {
            dp_netdev_flow_unref(ce->flow);
        }

        if (dp_netdev_flow_ref(flow)) {
            ce->flow = flow;
        } else {
            ce->flow = NULL;
        }
    }
    if (key) {
        netdev_flow_key_clone(&ce->key, key);
    }
}

static inline void
emc_insert(struct emc_cache *cache, const struct netdev_flow_key *key,
           struct dp_netdev_flow *flow)
{
    struct emc_entry *to_be_replaced = NULL;
    struct emc_entry *current_entry;

    EMC_FOR_EACH_POS_WITH_HASH(cache, current_entry, key->hash) {
        if (netdev_flow_key_equal(&current_entry->key, key)) {//换流
            /* We found the entry with the 'mf' miniflow */
            emc_change_entry(current_entry, flow, NULL);
            return;
        }

        /* Replacement policy: put the flow in an empty (not alive) entry, or
         * in the first entry where it can be */
        if (!to_be_replaced
            || (emc_entry_alive(to_be_replaced)
                && !emc_entry_alive(current_entry))
            || current_entry->key.hash < to_be_replaced->key.hash) {
            to_be_replaced = current_entry;
        }
    }
    /* We didn't find the miniflow in the cache.
     * The 'to_be_replaced' entry is where the new flow will be stored */

    emc_change_entry(to_be_replaced, flow, key);//淘汰掉to_be_replaced
}

//在ecm中查找
static inline void
emc_probabilistic_insert(struct dp_netdev_pmd_thread *pmd,
                         const struct netdev_flow_key *key,
                         struct dp_netdev_flow *flow)
{
    /* Insert an entry into the EMC based on probability value 'min'. By
     * default the value is UINT32_MAX / 100 which yields an insertion
     * probability of 1/100 ie. 1% */

    uint32_t min = pmd->ctx.emc_insert_min;

    if (min && random_uint32() <= min) {
        emc_insert(&(pmd->flow_cache).emc_cache, key, flow);
    }
}

//emc有一个key结构，它的current_entry->key结构需要与我们的key->mf完全一致才能认为匹配
static inline struct dp_netdev_flow *
emc_lookup(struct emc_cache *cache, const struct netdev_flow_key *key)
{
    struct emc_entry *current_entry;

    //仅执行两次查询
    EMC_FOR_EACH_POS_WITH_HASH(cache, current_entry, key->hash) {
        if (current_entry->key.hash == key->hash //hash相同
            && emc_entry_alive(current_entry) //emc实体有效
            && netdev_flow_key_equal_mf(&current_entry->key, &key->mf)) {//与key->mf完全相同

            /* We found the entry with the 'key->mf' miniflow */
            return current_entry->flow;//emc命中
        }
    }

    return NULL;
}

static inline const struct cmap_node *
smc_entry_get(struct dp_netdev_pmd_thread *pmd, const uint32_t hash)
{
    struct smc_cache *cache = &(pmd->flow_cache).smc_cache;
    struct smc_bucket *bucket = &cache->buckets[hash & SMC_MASK];
    uint16_t sig = hash >> 16;
    uint16_t index = UINT16_MAX;

    for (int i = 0; i < SMC_ENTRY_PER_BUCKET; i++) {
        if (bucket->sig[i] == sig) {
            index = bucket->flow_idx[i];
            break;
        }
    }
    if (index != UINT16_MAX) {
        return cmap_find_by_index(&pmd->flow_table, index);
    }
    return NULL;
}

static void
smc_clear_entry(struct smc_bucket *b, int idx)
{
    b->flow_idx[idx] = UINT16_MAX;
}

/* Insert the flow_table index into SMC. Insertion may fail when 1) SMC is
 * turned off, 2) the flow_table index is larger than uint16_t can handle.
 * If there is already an SMC entry having same signature, the index will be
 * updated. If there is no existing entry, but an empty entry is available,
 * the empty entry will be taken. If no empty entry or existing same signature,
 * a random entry from the hashed bucket will be picked. */
static inline void
smc_insert(struct dp_netdev_pmd_thread *pmd,
           const struct netdev_flow_key *key,
           uint32_t hash)
{
    struct smc_cache *smc_cache = &(pmd->flow_cache).smc_cache;
    struct smc_bucket *bucket = &smc_cache->buckets[key->hash & SMC_MASK];
    uint16_t index;
    uint32_t cmap_index;
    bool smc_enable_db;
    int i;

    atomic_read_relaxed(&pmd->dp->smc_enable_db, &smc_enable_db);
    if (!smc_enable_db) {
        return;
    }

    cmap_index = cmap_find_index(&pmd->flow_table, hash);
    index = (cmap_index >= UINT16_MAX) ? UINT16_MAX : (uint16_t)cmap_index;

    /* If the index is larger than SMC can handle (uint16_t), we don't
     * insert */
    if (index == UINT16_MAX) {
        return;
    }

    /* If an entry with same signature already exists, update the index */
    uint16_t sig = key->hash >> 16;
    for (i = 0; i < SMC_ENTRY_PER_BUCKET; i++) {
        if (bucket->sig[i] == sig) {
            bucket->flow_idx[i] = index;
            return;
        }
    }
    /* If there is an empty entry, occupy it. */
    for (i = 0; i < SMC_ENTRY_PER_BUCKET; i++) {
        if (bucket->flow_idx[i] == UINT16_MAX) {
            bucket->sig[i] = sig;
            bucket->flow_idx[i] = index;
            return;
        }
    }
    /* Otherwise, pick a random entry. */
    i = random_uint32() % SMC_ENTRY_PER_BUCKET;
    bucket->sig[i] = sig;
    bucket->flow_idx[i] = index;
}

//l2表查询办法：先找到dpcls,利用inport,然后通过dpcls_lookup进行查询rule,然后将rule转化为dp_netdev_flow
static struct dp_netdev_flow *
dp_netdev_pmd_lookup_flow(struct dp_netdev_pmd_thread *pmd,
                          const struct netdev_flow_key *key,
                          int *lookup_num_p)
{
    struct dpcls *cls;
    struct dpcls_rule *rule;
    //提取in_port
    odp_port_t in_port = u32_to_odp(MINIFLOW_GET_U32(&key->mf,
                                                     in_port.odp_port));
    struct dp_netdev_flow *netdev_flow = NULL;

    //返回入接口为in_port对应的表
    cls = dp_netdev_pmd_lookup_dpcls(pmd, in_port);
    if (OVS_LIKELY(cls)) {
    	//在相应的表中查询
        dpcls_lookup(cls, &key, &rule, 1, lookup_num_p);
        netdev_flow = dp_netdev_flow_cast(rule);
    }
    return netdev_flow;
}

static struct dp_netdev_flow *
dp_netdev_pmd_find_flow(const struct dp_netdev_pmd_thread *pmd,
                        const ovs_u128 *ufidp, const struct nlattr *key,
                        size_t key_len)
{
    struct dp_netdev_flow *netdev_flow;
    struct flow flow;
    ovs_u128 ufid;

    /* If a UFID is not provided, determine one based on the key. */
    if (!ufidp && key && key_len
        && !dpif_netdev_flow_from_nlattrs(key, key_len, &flow, false)) {
        dpif_flow_hash(pmd->dp->dpif, &flow, sizeof flow, &ufid);
        ufidp = &ufid;
    }

    if (ufidp) {
        CMAP_FOR_EACH_WITH_HASH (netdev_flow, node, dp_netdev_flow_hash(ufidp),
                                 &pmd->flow_table) {
            if (ovs_u128_equals(netdev_flow->ufid, *ufidp)) {
                return netdev_flow;
            }
        }
    }

    return NULL;
}

static void
get_dpif_flow_stats(const struct dp_netdev_flow *netdev_flow_,
                    struct dpif_flow_stats *stats)
{
    struct dp_netdev_flow *netdev_flow;
    unsigned long long n;
    long long used;
    uint16_t flags;

    netdev_flow = CONST_CAST(struct dp_netdev_flow *, netdev_flow_);

    atomic_read_relaxed(&netdev_flow->stats.packet_count, &n);
    stats->n_packets = n;
    atomic_read_relaxed(&netdev_flow->stats.byte_count, &n);
    stats->n_bytes = n;
    atomic_read_relaxed(&netdev_flow->stats.used, &used);
    stats->used = used;
    atomic_read_relaxed(&netdev_flow->stats.tcp_flags, &flags);
    stats->tcp_flags = flags;
}

/* Converts to the dpif_flow format, using 'key_buf' and 'mask_buf' for
 * storing the netlink-formatted key/mask. 'key_buf' may be the same as
 * 'mask_buf'. Actions will be returned without copying, by relying on RCU to
 * protect them. */
static void
dp_netdev_flow_to_dpif_flow(const struct dp_netdev_flow *netdev_flow,
                            struct ofpbuf *key_buf, struct ofpbuf *mask_buf,
                            struct dpif_flow *flow, bool terse)
{
    if (terse) {
        memset(flow, 0, sizeof *flow);
    } else {
        struct flow_wildcards wc;
        struct dp_netdev_actions *actions;
        size_t offset;
        struct odp_flow_key_parms odp_parms = {
            .flow = &netdev_flow->flow,
            .mask = &wc.masks,
            .support = dp_netdev_support,
        };

        miniflow_expand(&netdev_flow->cr.mask->mf, &wc.masks);
        /* in_port is exact matched, but we have left it out from the mask for
         * optimnization reasons. Add in_port back to the mask. */
        wc.masks.in_port.odp_port = ODPP_NONE;

        /* Key */
        offset = key_buf->size;
        flow->key = ofpbuf_tail(key_buf);
        odp_flow_key_from_flow(&odp_parms, key_buf);
        flow->key_len = key_buf->size - offset;

        /* Mask */
        offset = mask_buf->size;
        flow->mask = ofpbuf_tail(mask_buf);
        odp_parms.key_buf = key_buf;
        odp_flow_key_from_mask(&odp_parms, mask_buf);
        flow->mask_len = mask_buf->size - offset;

        /* Actions */
        actions = dp_netdev_flow_get_actions(netdev_flow);
        flow->actions = actions->actions;
        flow->actions_len = actions->size;
    }

    flow->ufid = netdev_flow->ufid;
    flow->ufid_present = true;
    flow->pmd_id = netdev_flow->pmd_id;
    get_dpif_flow_stats(netdev_flow, &flow->stats);

    flow->attrs.offloaded = false;
    flow->attrs.dp_layer = "ovs";
}

static int
dpif_netdev_mask_from_nlattrs(const struct nlattr *key, uint32_t key_len,
                              const struct nlattr *mask_key,
                              uint32_t mask_key_len, const struct flow *flow,
                              struct flow_wildcards *wc, bool probe)
{
    enum odp_key_fitness fitness;

    fitness = odp_flow_key_to_mask(mask_key, mask_key_len, wc, flow, NULL);
    if (fitness) {
    	//解析不成功，报错
        if (!probe) {
            /* This should not happen: it indicates that
             * odp_flow_key_from_mask() and odp_flow_key_to_mask()
             * disagree on the acceptable form of a mask.  Log the problem
             * as an error, with enough details to enable debugging. */
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

            if (!VLOG_DROP_ERR(&rl)) {
                struct ds s;

                ds_init(&s);
                odp_flow_format(key, key_len, mask_key, mask_key_len, NULL, &s,
                                true);
                VLOG_ERR("internal error parsing flow mask %s (%s)",
                ds_cstr(&s), odp_key_fitness_to_string(fitness));
                ds_destroy(&s);
            }
        }

        return EINVAL;
    }

    return 0;
}

//将key中的内容解析到flow中，如果解析成功返回0
static int
dpif_netdev_flow_from_nlattrs(const struct nlattr *key, uint32_t key_len,
                              struct flow *flow, bool probe)
{
    if (odp_flow_key_to_flow(key, key_len, flow, NULL)) {
    	//解析不是完全成功，报错
        if (!probe) {
            /* This should not happen: it indicates that
             * odp_flow_key_from_flow() and odp_flow_key_to_flow() disagree on
             * the acceptable form of a flow.  Log the problem as an error,
             * with enough details to enable debugging. */
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

            if (!VLOG_DROP_ERR(&rl)) {
                struct ds s;

                ds_init(&s);
                odp_flow_format(key, key_len, NULL, 0, NULL, &s, true);
                VLOG_ERR("internal error parsing flow key %s", ds_cstr(&s));
                ds_destroy(&s);
            }
        }

        return EINVAL;
    }

    if (flow->ct_state & DP_NETDEV_CS_UNSUPPORTED_MASK) {
    	//如果ct_state中设置的值与我们的存在不一致，则解析失败
        return EINVAL;
    }

    return 0;
}

static int
dpif_netdev_flow_get(const struct dpif *dpif, const struct dpif_flow_get *get)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_flow *netdev_flow;
    struct dp_netdev_pmd_thread *pmd;
    struct hmapx to_find = HMAPX_INITIALIZER(&to_find);
    struct hmapx_node *node;
    int error = EINVAL;

    if (get->pmd_id == PMD_ID_NULL) {
        CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
            if (dp_netdev_pmd_try_ref(pmd) && !hmapx_add(&to_find, pmd)) {
                dp_netdev_pmd_unref(pmd);
            }
        }
    } else {
        pmd = dp_netdev_get_pmd(dp, get->pmd_id);
        if (!pmd) {
            goto out;
        }
        hmapx_add(&to_find, pmd);
    }

    if (!hmapx_count(&to_find)) {
        goto out;
    }

    HMAPX_FOR_EACH (node, &to_find) {
        pmd = (struct dp_netdev_pmd_thread *) node->data;
        netdev_flow = dp_netdev_pmd_find_flow(pmd, get->ufid, get->key,
                                              get->key_len);
        if (netdev_flow) {
            dp_netdev_flow_to_dpif_flow(netdev_flow, get->buffer, get->buffer,
                                        get->flow, false);
            error = 0;
            break;
        } else {
            error = ENOENT;
        }
    }

    HMAPX_FOR_EACH (node, &to_find) {
        pmd = (struct dp_netdev_pmd_thread *) node->data;
        dp_netdev_pmd_unref(pmd);
    }
out:
    hmapx_destroy(&to_find);
    return error;
}

static void
dp_netdev_get_mega_ufid(const struct match *match, ovs_u128 *mega_ufid)
{
    struct flow masked_flow;
    size_t i;

    for (i = 0; i < sizeof(struct flow); i++) {
        ((uint8_t *)&masked_flow)[i] = ((uint8_t *)&match->flow)[i] &
                                       ((uint8_t *)&match->wc)[i];
    }
    dpif_flow_hash(NULL, &masked_flow, sizeof(struct flow), mega_ufid);
}

//向flow_table中加入流，match为匹配条件
static struct dp_netdev_flow *
dp_netdev_flow_add(struct dp_netdev_pmd_thread *pmd,
                   struct match *match, const ovs_u128 *ufid,
                   const struct nlattr *actions, size_t actions_len)
    OVS_REQUIRES(pmd->flow_mutex)
{
    struct dp_netdev_flow *flow;
    struct netdev_flow_key mask;
    struct dpcls *cls;

    /* Make sure in_port is exact matched before we read it. */
    ovs_assert(match->wc.masks.in_port.odp_port == ODPP_NONE);
    odp_port_t in_port = match->flow.in_port.odp_port;

    /* As we select the dpcls based on the port number, each netdev flow
     * belonging to the same dpcls will have the same odp_port value.
     * For performance reasons we wildcard odp_port here in the mask.  In the
     * typical case dp_hash is also wildcarded, and the resulting 8-byte
     * chunk {dp_hash, in_port} will be ignored by netdev_flow_mask_init() and
     * will not be part of the subtable mask.
     * This will speed up the hash computation during dpcls_lookup() because
     * there is one less call to hash_add64() in this case. */
    match->wc.masks.in_port.odp_port = 0;
    netdev_flow_mask_init(&mask, match);
    match->wc.masks.in_port.odp_port = ODPP_NONE;

    /* Make sure wc does not have metadata. */
    ovs_assert(!FLOWMAP_HAS_FIELD(&mask.mf.map, metadata)
               && !FLOWMAP_HAS_FIELD(&mask.mf.map, regs));

    /* Do not allocate extra space. */
    flow = xmalloc(sizeof *flow - sizeof flow->cr.flow.mf + mask.len);//这个flow的空间不完全（在这个结构的前半部分按成员放了数据，故最后面的不要）
    memset(&flow->stats, 0, sizeof flow->stats);
    flow->dead = false;
    flow->batch = NULL;
    flow->mark = INVALID_FLOW_MARK;
    *CONST_CAST(unsigned *, &flow->pmd_id) = pmd->core_id;
    *CONST_CAST(struct flow *, &flow->flow) = match->flow;
    *CONST_CAST(ovs_u128 *, &flow->ufid) = *ufid;
    ovs_refcount_init(&flow->ref_cnt);
    ovsrcu_set(&flow->actions, dp_netdev_actions_create(actions, actions_len));//申请空间，并存放actions到flow中

    dp_netdev_get_mega_ufid(match, CONST_CAST(ovs_u128 *, &flow->mega_ufid));
    netdev_flow_key_init_masked(&flow->cr.flow, &match->flow, &mask);

    /* Select dpcls for in_port. Relies on in_port to be exact match. */
    //如果这个in_port不存在，则创建对应dpcls
    cls = dp_netdev_pmd_find_dpcls(pmd, in_port);
    dpcls_insert(cls, &flow->cr, &mask);

    //将flow加入到flow_table表中，flow_table为l2表
    cmap_insert(&pmd->flow_table, CONST_CAST(struct cmap_node *, &flow->node),
                dp_netdev_flow_hash(&flow->ufid));

    queue_netdev_flow_put(pmd, flow, match, actions, actions_len);

    if (OVS_UNLIKELY(!VLOG_DROP_DBG((&upcall_rl)))) {//调试代码
        struct ds ds = DS_EMPTY_INITIALIZER;
        struct ofpbuf key_buf, mask_buf;
        struct odp_flow_key_parms odp_parms = {
            .flow = &match->flow,
            .mask = &match->wc.masks,
            .support = dp_netdev_support,
        };

        ofpbuf_init(&key_buf, 0);
        ofpbuf_init(&mask_buf, 0);

        odp_flow_key_from_flow(&odp_parms, &key_buf);
        odp_parms.key_buf = &key_buf;
        odp_flow_key_from_mask(&odp_parms, &mask_buf);

        //开始dump flow的值
        ds_put_cstr(&ds, "flow_add: ");
        odp_format_ufid(ufid, &ds);//输出ufid:
        ds_put_cstr(&ds, " ");
        odp_flow_format(key_buf.data, key_buf.size,
                        mask_buf.data, mask_buf.size,
                        NULL, &ds, false);
        //输出action
        ds_put_cstr(&ds, ", actions:");
        format_odp_actions(&ds, actions, actions_len, NULL);

        VLOG_DBG("%s", ds_cstr(&ds));

        ofpbuf_uninit(&key_buf);
        ofpbuf_uninit(&mask_buf);

        /* Add a printout of the actual match installed. */
        struct match m;
        ds_clear(&ds);
        ds_put_cstr(&ds, "flow match: ");
        miniflow_expand(&flow->cr.flow.mf, &m.flow);
        miniflow_expand(&flow->cr.mask->mf, &m.wc.masks);
        memset(&m.tun_md, 0, sizeof m.tun_md);
        match_format(&m, NULL, &ds, OFP_DEFAULT_PRIORITY);

        VLOG_DBG("%s", ds_cstr(&ds));

        ds_destroy(&ds);
    }

    return flow;
}

static int
flow_put_on_pmd(struct dp_netdev_pmd_thread *pmd,//要下发到哪个pmd上
                struct netdev_flow_key *key,//匹配时的比对结果
                struct match *match,//匹配时的匹配条件
                ovs_u128 *ufid,//cookie值
                const struct dpif_flow_put *put,//要下发的规则
                struct dpif_flow_stats *stats)
{
    struct dp_netdev_flow *netdev_flow;
    int error = 0;

    if (stats) {
    	//如果要收集状态，则清空状态
        memset(stats, 0, sizeof *stats);
    }

    ovs_mutex_lock(&pmd->flow_mutex);//加锁
    //在此pmd上查询此key
    netdev_flow = dp_netdev_pmd_lookup_flow(pmd, key, NULL);
    if (!netdev_flow) {
    	//没有找到此flow
        if (put->flags & DPIF_FP_CREATE) {
        	//容许创建，且没有达到flow最大数，则进行创建
            if (cmap_count(&pmd->flow_table) < MAX_FLOWS) {
                dp_netdev_flow_add(pmd, match, ufid, put->actions,
                                   put->actions_len);
                error = 0;
            } else {
                error = EFBIG;
            }
        } else {
            error = ENOENT;
        }
    } else {
    	//找到了此flow，如果容许修改，则直接修改action
        if (put->flags & DPIF_FP_MODIFY) {
            struct dp_netdev_actions *new_actions;
            struct dp_netdev_actions *old_actions;

            new_actions = dp_netdev_actions_create(put->actions,
                                                   put->actions_len);

            old_actions = dp_netdev_flow_get_actions(netdev_flow);
            ovsrcu_set(&netdev_flow->actions, new_actions);

            queue_netdev_flow_put(pmd, netdev_flow, match,
                                  put->actions, put->actions_len);

            if (stats) {
                get_dpif_flow_stats(netdev_flow, stats);
            }
            if (put->flags & DPIF_FP_ZERO_STATS) {
                /* XXX: The userspace datapath uses thread local statistics
                 * (for flows), which should be updated only by the owning
                 * thread.  Since we cannot write on stats memory here,
                 * we choose not to support this flag.  Please note:
                 * - This feature is currently used only by dpctl commands with
                 *   option --clear.
                 * - Should the need arise, this operation can be implemented
                 *   by keeping a base value (to be update here) for each
                 *   counter, and subtracting it before outputting the stats */
                error = EOPNOTSUPP;
            }

            ovsrcu_postpone(dp_netdev_actions_free, old_actions);
        } else if (put->flags & DPIF_FP_CREATE) {
            error = EEXIST;
        } else {
            /* Overlapping flow. */
            error = EINVAL;
        }
    }
    ovs_mutex_unlock(&pmd->flow_mutex);
    return error;
}

static int
dpif_netdev_flow_put(struct dpif *dpif, const struct dpif_flow_put *put)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct netdev_flow_key key, mask;
    struct dp_netdev_pmd_thread *pmd;
    struct match match;
    ovs_u128 ufid;
    int error;
    bool probe = put->flags & DPIF_FP_PROBE;

    if (put->stats) {
    	//如果put中设置了stats，则将其置0
        memset(put->stats, 0, sizeof *put->stats);
    }
    //将put中的key解析到match.flow中
    error = dpif_netdev_flow_from_nlattrs(put->key, put->key_len, &match.flow,
                                          probe);
    if (error) {
    	//解析失败
        return error;
    }
    //将put中的mask解析到match.wc中
    error = dpif_netdev_mask_from_nlattrs(put->key, put->key_len,
                                          put->mask, put->mask_len,
                                          &match.flow, &match.wc, probe);
    if (error) {
    	//解析失败
        return error;
    }

    if (put->ufid) {
        ufid = *put->ufid;
    } else {
    	//没有为此flow填写ufid,生成一个ufid
        dpif_flow_hash(dpif, &match.flow, sizeof match.flow, &ufid);
    }

    /* The Netlink encoding of datapath flow keys cannot express
     * wildcarding the presence of a VLAN tag. Instead, a missing VLAN
     * tag is interpreted as exact match on the fact that there is no
     * VLAN.  Unless we refactor a lot of code that translates between
     * Netlink and struct flow representations, we have to do the same
     * here.  This must be in sync with 'match' in handle_packet_upcall(). */
    if (!match.wc.masks.vlans[0].tci) {
        match.wc.masks.vlans[0].tci = htons(0xffff);
    }

    /* Must produce a netdev_flow_key for lookup.
     * Use the same method as employed to create the key when adding
     * the flow to the dplcs to make sure they match. */
    //采用match填充mask
    netdev_flow_mask_init(&mask, &match);
    //实现match.flow & mask后，将其结果存放在key中
    netdev_flow_key_init_masked(&key, &match.flow, &mask);

    if (put->pmd_id == PMD_ID_NULL) {
    	//如果没有指定pmd_id,则为每个pmd下发此flow
        if (cmap_count(&dp->poll_threads) == 0) {
            return EINVAL;
        }
        CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
            struct dpif_flow_stats pmd_stats;
            int pmd_error;

            pmd_error = flow_put_on_pmd(pmd, &key, &match, &ufid, put,
                                        &pmd_stats);
            if (pmd_error) {
                error = pmd_error;//出错了，继续下发（这里应打一句log)
            } else if (put->stats) {
                put->stats->n_packets += pmd_stats.n_packets;
                put->stats->n_bytes += pmd_stats.n_bytes;
                put->stats->used = MAX(put->stats->used, pmd_stats.used);
                put->stats->tcp_flags |= pmd_stats.tcp_flags;
            }
        }
    } else {
    	//指定了pmd_id,找到这个pmd_id,并为其下发此flow
        pmd = dp_netdev_get_pmd(dp, put->pmd_id);
        if (!pmd) {
            return EINVAL;
        }
        error = flow_put_on_pmd(pmd, &key, &match, &ufid, put, put->stats);
        dp_netdev_pmd_unref(pmd);
    }

    return error;
}

static int
flow_del_on_pmd(struct dp_netdev_pmd_thread *pmd,
                struct dpif_flow_stats *stats,
                const struct dpif_flow_del *del)
{
    struct dp_netdev_flow *netdev_flow;
    int error = 0;

    ovs_mutex_lock(&pmd->flow_mutex);
    netdev_flow = dp_netdev_pmd_find_flow(pmd, del->ufid, del->key,
                                          del->key_len);
    if (netdev_flow) {
        if (stats) {
            get_dpif_flow_stats(netdev_flow, stats);
        }
        dp_netdev_pmd_remove_flow(pmd, netdev_flow);
    } else {
        error = ENOENT;
    }
    ovs_mutex_unlock(&pmd->flow_mutex);

    return error;
}

static int
dpif_netdev_flow_del(struct dpif *dpif, const struct dpif_flow_del *del)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_pmd_thread *pmd;
    int error = 0;

    if (del->stats) {
        memset(del->stats, 0, sizeof *del->stats);
    }

    if (del->pmd_id == PMD_ID_NULL) {
        if (cmap_count(&dp->poll_threads) == 0) {
            return EINVAL;
        }
        CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
            struct dpif_flow_stats pmd_stats;
            int pmd_error;

            pmd_error = flow_del_on_pmd(pmd, &pmd_stats, del);
            if (pmd_error) {
                error = pmd_error;
            } else if (del->stats) {
                del->stats->n_packets += pmd_stats.n_packets;
                del->stats->n_bytes += pmd_stats.n_bytes;
                del->stats->used = MAX(del->stats->used, pmd_stats.used);
                del->stats->tcp_flags |= pmd_stats.tcp_flags;
            }
        }
    } else {
        pmd = dp_netdev_get_pmd(dp, del->pmd_id);
        if (!pmd) {
            return EINVAL;
        }
        error = flow_del_on_pmd(pmd, del->stats, del);
        dp_netdev_pmd_unref(pmd);
    }


    return error;
}

struct dpif_netdev_flow_dump {
    struct dpif_flow_dump up;
    struct cmap_position poll_thread_pos;
    struct cmap_position flow_pos;
    struct dp_netdev_pmd_thread *cur_pmd;
    int status;
    struct ovs_mutex mutex;
};

static struct dpif_netdev_flow_dump *
dpif_netdev_flow_dump_cast(struct dpif_flow_dump *dump)
{
    return CONTAINER_OF(dump, struct dpif_netdev_flow_dump, up);
}

static struct dpif_flow_dump *
dpif_netdev_flow_dump_create(const struct dpif *dpif_, bool terse,
                             struct dpif_flow_dump_types *types OVS_UNUSED)
{
    struct dpif_netdev_flow_dump *dump;

    dump = xzalloc(sizeof *dump);
    dpif_flow_dump_init(&dump->up, dpif_);
    dump->up.terse = terse;
    ovs_mutex_init(&dump->mutex);

    return &dump->up;
}

static int
dpif_netdev_flow_dump_destroy(struct dpif_flow_dump *dump_)
{
    struct dpif_netdev_flow_dump *dump = dpif_netdev_flow_dump_cast(dump_);

    ovs_mutex_destroy(&dump->mutex);
    free(dump);
    return 0;
}

struct dpif_netdev_flow_dump_thread {
    struct dpif_flow_dump_thread up;
    struct dpif_netdev_flow_dump *dump;
    struct odputil_keybuf keybuf[FLOW_DUMP_MAX_BATCH];
    struct odputil_keybuf maskbuf[FLOW_DUMP_MAX_BATCH];
};

static struct dpif_netdev_flow_dump_thread *
dpif_netdev_flow_dump_thread_cast(struct dpif_flow_dump_thread *thread)
{
    return CONTAINER_OF(thread, struct dpif_netdev_flow_dump_thread, up);
}

static struct dpif_flow_dump_thread *
dpif_netdev_flow_dump_thread_create(struct dpif_flow_dump *dump_)
{
    struct dpif_netdev_flow_dump *dump = dpif_netdev_flow_dump_cast(dump_);
    struct dpif_netdev_flow_dump_thread *thread;

    thread = xmalloc(sizeof *thread);
    dpif_flow_dump_thread_init(&thread->up, &dump->up);
    thread->dump = dump;
    return &thread->up;
}

static void
dpif_netdev_flow_dump_thread_destroy(struct dpif_flow_dump_thread *thread_)
{
    struct dpif_netdev_flow_dump_thread *thread
        = dpif_netdev_flow_dump_thread_cast(thread_);

    free(thread);
}

static int
dpif_netdev_flow_dump_next(struct dpif_flow_dump_thread *thread_,
                           struct dpif_flow *flows, int max_flows)
{
    struct dpif_netdev_flow_dump_thread *thread
        = dpif_netdev_flow_dump_thread_cast(thread_);
    struct dpif_netdev_flow_dump *dump = thread->dump;
    struct dp_netdev_flow *netdev_flows[FLOW_DUMP_MAX_BATCH];
    int n_flows = 0;
    int i;

    ovs_mutex_lock(&dump->mutex);
    if (!dump->status) {
        struct dpif_netdev *dpif = dpif_netdev_cast(thread->up.dpif);
        struct dp_netdev *dp = get_dp_netdev(&dpif->dpif);
        struct dp_netdev_pmd_thread *pmd = dump->cur_pmd;
        int flow_limit = MIN(max_flows, FLOW_DUMP_MAX_BATCH);

        /* First call to dump_next(), extracts the first pmd thread.
         * If there is no pmd thread, returns immediately. */
        if (!pmd) {
            pmd = dp_netdev_pmd_get_next(dp, &dump->poll_thread_pos);
            if (!pmd) {
                ovs_mutex_unlock(&dump->mutex);
                return n_flows;

            }
        }

        do {
            for (n_flows = 0; n_flows < flow_limit; n_flows++) {
                struct cmap_node *node;

                node = cmap_next_position(&pmd->flow_table, &dump->flow_pos);
                if (!node) {
                    break;
                }
                netdev_flows[n_flows] = CONTAINER_OF(node,
                                                     struct dp_netdev_flow,
                                                     node);
            }
            /* When finishing dumping the current pmd thread, moves to
             * the next. */
            if (n_flows < flow_limit) {
                memset(&dump->flow_pos, 0, sizeof dump->flow_pos);
                dp_netdev_pmd_unref(pmd);
                pmd = dp_netdev_pmd_get_next(dp, &dump->poll_thread_pos);
                if (!pmd) {
                    dump->status = EOF;
                    break;
                }
            }
            /* Keeps the reference to next caller. */
            dump->cur_pmd = pmd;

            /* If the current dump is empty, do not exit the loop, since the
             * remaining pmds could have flows to be dumped.  Just dumps again
             * on the new 'pmd'. */
        } while (!n_flows);
    }
    ovs_mutex_unlock(&dump->mutex);

    for (i = 0; i < n_flows; i++) {
        struct odputil_keybuf *maskbuf = &thread->maskbuf[i];
        struct odputil_keybuf *keybuf = &thread->keybuf[i];
        struct dp_netdev_flow *netdev_flow = netdev_flows[i];
        struct dpif_flow *f = &flows[i];
        struct ofpbuf key, mask;

        ofpbuf_use_stack(&key, keybuf, sizeof *keybuf);
        ofpbuf_use_stack(&mask, maskbuf, sizeof *maskbuf);
        dp_netdev_flow_to_dpif_flow(netdev_flow, &key, &mask, f,
                                    dump->up.terse);
    }

    return n_flows;
}

static int
dpif_netdev_execute(struct dpif *dpif, struct dpif_execute *execute)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_pmd_thread *pmd;
    struct dp_packet_batch pp;

    if (dp_packet_size(execute->packet) < ETH_HEADER_LEN ||
        dp_packet_size(execute->packet) > UINT16_MAX) {
        return EINVAL;
    }

    /* Tries finding the 'pmd'.  If NULL is returned, that means
     * the current thread is a non-pmd thread and should use
     * dp_netdev_get_pmd(dp, NON_PMD_CORE_ID). */
    pmd = ovsthread_getspecific(dp->per_pmd_key);
    if (!pmd) {
        pmd = dp_netdev_get_pmd(dp, NON_PMD_CORE_ID);
        if (!pmd) {
            return EBUSY;
        }
    }

    if (execute->probe) {
        /* If this is part of a probe, Drop the packet, since executing
         * the action may actually cause spurious packets be sent into
         * the network. */
        if (pmd->core_id == NON_PMD_CORE_ID) {
            dp_netdev_pmd_unref(pmd);
        }
        return 0;
    }

    /* If the current thread is non-pmd thread, acquires
     * the 'non_pmd_mutex'. */
    if (pmd->core_id == NON_PMD_CORE_ID) {
        ovs_mutex_lock(&dp->non_pmd_mutex);
    }

    /* Update current time in PMD context. We don't care about EMC insertion
     * probability, because we are on a slow path. */
    pmd_thread_ctx_time_update(pmd);

    /* The action processing expects the RSS hash to be valid, because
     * it's always initialized at the beginning of datapath processing.
     * In this case, though, 'execute->packet' may not have gone through
     * the datapath at all, it may have been generated by the upper layer
     * (OpenFlow packet-out, BFD frame, ...). */
    if (!dp_packet_rss_valid(execute->packet)) {
        dp_packet_set_rss_hash(execute->packet,
                               flow_hash_5tuple(execute->flow, 0));
    }

    dp_packet_batch_init_packet(&pp, execute->packet);
    pp.do_not_steal = true;
    dp_netdev_execute_actions(pmd, &pp, false, execute->flow,
                              execute->actions, execute->actions_len);
    dp_netdev_pmd_flush_output_packets(pmd, true);

    if (pmd->core_id == NON_PMD_CORE_ID) {
        ovs_mutex_unlock(&dp->non_pmd_mutex);
        dp_netdev_pmd_unref(pmd);
    }

    return 0;
}

static void
dpif_netdev_operate(struct dpif *dpif, struct dpif_op **ops, size_t n_ops,
                    enum dpif_offload_type offload_type OVS_UNUSED)
{
    size_t i;

    for (i = 0; i < n_ops; i++) {
        struct dpif_op *op = ops[i];

        //按类型操作
        switch (op->type) {
        case DPIF_OP_FLOW_PUT:
            op->error = dpif_netdev_flow_put(dpif, &op->flow_put);
            break;

        case DPIF_OP_FLOW_DEL:
            op->error = dpif_netdev_flow_del(dpif, &op->flow_del);
            break;

        case DPIF_OP_EXECUTE:
            op->error = dpif_netdev_execute(dpif, &op->execute);
            break;

        case DPIF_OP_FLOW_GET:
            op->error = dpif_netdev_flow_get(dpif, &op->flow_get);
            break;
        }
    }
}

/* Enable or Disable PMD auto load balancing. */
static void
set_pmd_auto_lb(struct dp_netdev *dp)
{
    unsigned int cnt = 0;
    struct dp_netdev_pmd_thread *pmd;
    struct pmd_auto_lb *pmd_alb = &dp->pmd_alb;

    bool enable_alb = false;
    bool multi_rxq = false;
    bool pmd_rxq_assign_cyc = dp->pmd_rxq_assign_cyc;

    /* Ensure that there is at least 2 non-isolated PMDs and
     * one of them is polling more than one rxq. */
    CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
        if (pmd->core_id == NON_PMD_CORE_ID || pmd->isolated) {
            continue;
        }

        if (hmap_count(&pmd->poll_list) > 1) {
            multi_rxq = true;
        }
        if (cnt && multi_rxq) {
                enable_alb = true;
                break;
        }
        cnt++;
    }

    /* Enable auto LB if it is requested and cycle based assignment is true. */
    enable_alb = enable_alb && pmd_rxq_assign_cyc &&
                    pmd_alb->auto_lb_requested;

    if (pmd_alb->is_enabled != enable_alb) {
        pmd_alb->is_enabled = enable_alb;
        if (pmd_alb->is_enabled) {
            VLOG_INFO("PMD auto load balance is enabled "
                      "(with rebalance interval:%"PRIu64" msec)",
                       pmd_alb->rebalance_intvl);
        } else {
            pmd_alb->rebalance_poll_timer = 0;
            VLOG_INFO("PMD auto load balance is disabled");
        }
    }

}

/* Applies datapath configuration from the database. Some of the changes are
 * actually applied in dpif_netdev_run(). */
//重新设置pmd_cmask
static int
dpif_netdev_set_config(struct dpif *dpif, const struct smap *other_config)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    const char *cmask = smap_get(other_config, "pmd-cpu-mask");
    const char *pmd_rxq_assign = smap_get_def(other_config, "pmd-rxq-assign",
                                             "cycles");
    unsigned long long insert_prob =
        smap_get_ullong(other_config, "emc-insert-inv-prob",
                        DEFAULT_EM_FLOW_INSERT_INV_PROB);
    uint32_t insert_min, cur_min;
    uint32_t tx_flush_interval, cur_tx_flush_interval;
    uint64_t rebalance_intvl;

    tx_flush_interval = smap_get_int(other_config, "tx-flush-interval",
                                     DEFAULT_TX_FLUSH_INTERVAL);
    atomic_read_relaxed(&dp->tx_flush_interval, &cur_tx_flush_interval);
    if (tx_flush_interval != cur_tx_flush_interval) {
        atomic_store_relaxed(&dp->tx_flush_interval, tx_flush_interval);
        VLOG_INFO("Flushing interval for tx queues set to %"PRIu32" us",
                  tx_flush_interval);
    }

    if (!nullable_string_is_equal(dp->pmd_cmask, cmask)) {
        free(dp->pmd_cmask);
        dp->pmd_cmask = nullable_xstrdup(cmask);
        dp_netdev_request_reconfigure(dp);//通知dp配置发生变化
    }

    atomic_read_relaxed(&dp->emc_insert_min, &cur_min);
    if (insert_prob <= UINT32_MAX) {
        insert_min = insert_prob == 0 ? 0 : UINT32_MAX / insert_prob;
    } else {
        insert_min = DEFAULT_EM_FLOW_INSERT_MIN;
        insert_prob = DEFAULT_EM_FLOW_INSERT_INV_PROB;
    }

    if (insert_min != cur_min) {
        atomic_store_relaxed(&dp->emc_insert_min, insert_min);
        if (insert_min == 0) {
            VLOG_INFO("EMC insertion probability changed to zero");
        } else {
            VLOG_INFO("EMC insertion probability changed to 1/%llu (~%.2f%%)",
                      insert_prob, (100 / (float)insert_prob));
        }
    }

    bool perf_enabled = smap_get_bool(other_config, "pmd-perf-metrics", false);
    bool cur_perf_enabled;
    atomic_read_relaxed(&dp->pmd_perf_metrics, &cur_perf_enabled);
    if (perf_enabled != cur_perf_enabled) {
        atomic_store_relaxed(&dp->pmd_perf_metrics, perf_enabled);
        if (perf_enabled) {
            VLOG_INFO("PMD performance metrics collection enabled");
        } else {
            VLOG_INFO("PMD performance metrics collection disabled");
        }
    }

    bool smc_enable = smap_get_bool(other_config, "smc-enable", false);
    bool cur_smc;
    atomic_read_relaxed(&dp->smc_enable_db, &cur_smc);
    if (smc_enable != cur_smc) {
        atomic_store_relaxed(&dp->smc_enable_db, smc_enable);
        if (smc_enable) {
            VLOG_INFO("SMC cache is enabled");
        } else {
            VLOG_INFO("SMC cache is disabled");
        }
    }

    bool pmd_rxq_assign_cyc = !strcmp(pmd_rxq_assign, "cycles");
    if (!pmd_rxq_assign_cyc && strcmp(pmd_rxq_assign, "roundrobin")) {
        VLOG_WARN("Unsupported Rxq to PMD assignment mode in pmd-rxq-assign. "
                      "Defaulting to 'cycles'.");
        pmd_rxq_assign_cyc = true;
        pmd_rxq_assign = "cycles";
    }
    if (dp->pmd_rxq_assign_cyc != pmd_rxq_assign_cyc) {
        dp->pmd_rxq_assign_cyc = pmd_rxq_assign_cyc;
        VLOG_INFO("Rxq to PMD assignment mode changed to: \'%s\'.",
                  pmd_rxq_assign);
        dp_netdev_request_reconfigure(dp);
    }

    struct pmd_auto_lb *pmd_alb = &dp->pmd_alb;
    pmd_alb->auto_lb_requested = smap_get_bool(other_config, "pmd-auto-lb",
                              false);

    rebalance_intvl = smap_get_int(other_config, "pmd-auto-lb-rebal-interval",
                              ALB_PMD_REBALANCE_POLL_INTERVAL);

    /* Input is in min, convert it to msec. */
    rebalance_intvl =
        rebalance_intvl ? rebalance_intvl * MIN_TO_MSEC : MIN_TO_MSEC;

    if (pmd_alb->rebalance_intvl != rebalance_intvl) {
        pmd_alb->rebalance_intvl = rebalance_intvl;
    }

    set_pmd_auto_lb(dp);
    return 0;
}

/* Parses affinity list and returns result in 'core_ids'. */
static int
parse_affinity_list(const char *affinity_list, unsigned *core_ids, int n_rxq)
{
    unsigned i;
    char *list, *copy, *key, *value;
    int error = 0;

    for (i = 0; i < n_rxq; i++) {
        core_ids[i] = OVS_CORE_UNSPEC;
    }

    if (!affinity_list) {
        return 0;
    }

    list = copy = xstrdup(affinity_list);

    while (ofputil_parse_key_value(&list, &key, &value)) {
        int rxq_id, core_id;

        //提取rxq_id对应的core_id
        if (!str_to_int(key, 0, &rxq_id) || rxq_id < 0
            || !str_to_int(value, 0, &core_id) || core_id < 0) {
            error = EINVAL;
            break;
        }

        //如果配置中有大于n_rxq的配置，忽略
        if (rxq_id < n_rxq) {
            core_ids[rxq_id] = core_id;
        }
    }

    free(copy);
    return error;
}

/* Parses 'affinity_list' and applies configuration if it is valid. */
//配置收队列的cpu亲呢性
static int
dpif_netdev_port_set_rxq_affinity(struct dp_netdev_port *port,
                                  const char *affinity_list)
{
    unsigned *core_ids, i;
    int error = 0;

    //在core_ids中收集n_rxq个队列分别由哪些core负责
    core_ids = xmalloc(port->n_rxq * sizeof *core_ids);
    if (parse_affinity_list(affinity_list, core_ids, port->n_rxq)) {
        error = EINVAL;
        goto exit;
    }

    for (i = 0; i < port->n_rxq; i++) {
        port->rxqs[i].core_id = core_ids[i];
    }

exit:
    free(core_ids);
    return error;
}

/* Returns 'true' if one of the 'port's RX queues exists in 'poll_list'
 * of given PMD thread. */
static bool
dpif_netdev_pmd_polls_port(struct dp_netdev_pmd_thread *pmd,
                           struct dp_netdev_port *port)
    OVS_EXCLUDED(pmd->port_mutex)
{
    struct rxq_poll *poll;
    bool found = false;

    ovs_mutex_lock(&pmd->port_mutex);
    HMAP_FOR_EACH (poll, node, &pmd->poll_list) {
        if (port == poll->rxq->port) {
            found = true;
            break;
        }
    }
    ovs_mutex_unlock(&pmd->port_mutex);
    return found;
}

/* Updates port configuration from the database.  The changes are actually
 * applied in dpif_netdev_run(). */
static int
dpif_netdev_port_set_config(struct dpif *dpif, odp_port_t port_no,
                            const struct smap *cfg)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_port *port;
    int error = 0;
    const char *affinity_list = smap_get(cfg, "pmd-rxq-affinity");
    bool emc_enabled = smap_get_bool(cfg, "emc-enable", true);

    ovs_mutex_lock(&dp->port_mutex);
    error = get_port_by_number(dp, port_no, &port);
    if (error) {
        goto unlock;
    }

    if (emc_enabled != port->emc_enabled) {
        struct dp_netdev_pmd_thread *pmd;
        struct ds ds = DS_EMPTY_INITIALIZER;
        uint32_t cur_min, insert_prob;

        port->emc_enabled = emc_enabled;
        /* Mark for reload all the threads that polls this port and request
         * for reconfiguration for the actual reloading of threads. */
        CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
            if (dpif_netdev_pmd_polls_port(pmd, port)) {
                pmd->need_reload = true;
            }
        }
        dp_netdev_request_reconfigure(dp);

        ds_put_format(&ds, "%s: EMC has been %s.",
                      netdev_get_name(port->netdev),
                      (emc_enabled) ? "enabled" : "disabled");
        if (emc_enabled) {
            ds_put_cstr(&ds, " Current insertion probability is ");
            atomic_read_relaxed(&dp->emc_insert_min, &cur_min);
            if (!cur_min) {
                ds_put_cstr(&ds, "zero.");
            } else {
                insert_prob = UINT32_MAX / cur_min;
                ds_put_format(&ds, "1/%"PRIu32" (~%.2f%%).",
                              insert_prob, 100 / (float) insert_prob);
            }
        }
        VLOG_INFO("%s", ds_cstr(&ds));
        ds_destroy(&ds);
    }

    /* Checking for RXq affinity changes. */
    if (!netdev_is_pmd(port->netdev)
        || nullable_string_is_equal(affinity_list, port->rxq_affinity_list)) {
        goto unlock;
    }

    error = dpif_netdev_port_set_rxq_affinity(port, affinity_list);
    if (error) {
        goto unlock;
    }
    free(port->rxq_affinity_list);
    port->rxq_affinity_list = nullable_xstrdup(affinity_list);

    dp_netdev_request_reconfigure(dp);
unlock:
    ovs_mutex_unlock(&dp->port_mutex);
    return error;
}

static int
dpif_netdev_queue_to_priority(const struct dpif *dpif OVS_UNUSED,
                              uint32_t queue_id, uint32_t *priority)
{
    *priority = queue_id;
    return 0;
}


/* Creates and returns a new 'struct dp_netdev_actions', whose actions are
 * a copy of the 'size' bytes of 'actions' input parameters. */
struct dp_netdev_actions *
dp_netdev_actions_create(const struct nlattr *actions, size_t size)
{
    struct dp_netdev_actions *netdev_actions;

    netdev_actions = xmalloc(sizeof *netdev_actions + size);
    memcpy(netdev_actions->actions, actions, size);
    netdev_actions->size = size;

    return netdev_actions;
}

//从flow中取出action
struct dp_netdev_actions *
dp_netdev_flow_get_actions(const struct dp_netdev_flow *flow)
{
    return ovsrcu_get(struct dp_netdev_actions *, &flow->actions);
}

static void
dp_netdev_actions_free(struct dp_netdev_actions *actions)
{
    free(actions);
}

static void
dp_netdev_rxq_set_cycles(struct dp_netdev_rxq *rx,
                         enum rxq_cycles_counter_type type,
                         unsigned long long cycles)
{
   atomic_store_relaxed(&rx->cycles[type], cycles);
}

static void
dp_netdev_rxq_add_cycles(struct dp_netdev_rxq *rx,
                         enum rxq_cycles_counter_type type,
                         unsigned long long cycles)
{
    non_atomic_ullong_add(&rx->cycles[type], cycles);
}

static uint64_t
dp_netdev_rxq_get_cycles(struct dp_netdev_rxq *rx,
                         enum rxq_cycles_counter_type type)
{
    unsigned long long processing_cycles;
    atomic_read_relaxed(&rx->cycles[type], &processing_cycles);
    return processing_cycles;
}

static void
dp_netdev_rxq_set_intrvl_cycles(struct dp_netdev_rxq *rx,
                                unsigned long long cycles)
{
    unsigned int idx = rx->intrvl_idx++ % PMD_RXQ_INTERVAL_MAX;
    atomic_store_relaxed(&rx->cycles_intrvl[idx], cycles);
}

static uint64_t
dp_netdev_rxq_get_intrvl_cycles(struct dp_netdev_rxq *rx, unsigned idx)
{
    unsigned long long processing_cycles;
    atomic_read_relaxed(&rx->cycles_intrvl[idx], &processing_cycles);
    return processing_cycles;
}

#if ATOMIC_ALWAYS_LOCK_FREE_8B
static inline bool
pmd_perf_metrics_enabled(const struct dp_netdev_pmd_thread *pmd)
{
    bool pmd_perf_enabled;
    atomic_read_relaxed(&pmd->dp->pmd_perf_metrics, &pmd_perf_enabled);
    return pmd_perf_enabled;
}
#else
/* If stores and reads of 64-bit integers are not atomic, the full PMD
 * performance metrics are not available as locked access to 64 bit
 * integers would be prohibitively expensive. */
static inline bool
pmd_perf_metrics_enabled(const struct dp_netdev_pmd_thread *pmd OVS_UNUSED)
{
    return false;
}
#endif

static int
dp_netdev_pmd_flush_output_on_port(struct dp_netdev_pmd_thread *pmd,
                                   struct tx_port *p)
{
    int i;
    int tx_qid;
    int output_cnt;
    bool dynamic_txqs;
    struct cycle_timer timer;
    uint64_t cycles;
    uint32_t tx_flush_interval;

    cycle_timer_start(&pmd->perf_stats, &timer);

    dynamic_txqs = p->port->dynamic_txqs;
    if (dynamic_txqs) {
        tx_qid = dpif_netdev_xps_get_tx_qid(pmd, p);
    } else {
        tx_qid = pmd->static_tx_qid;
    }

    output_cnt = dp_packet_batch_size(&p->output_pkts);
    ovs_assert(output_cnt > 0);

    netdev_send(p->port->netdev, tx_qid, &p->output_pkts, dynamic_txqs);
    dp_packet_batch_init(&p->output_pkts);

    /* Update time of the next flush. */
    atomic_read_relaxed(&pmd->dp->tx_flush_interval, &tx_flush_interval);
    p->flush_time = pmd->ctx.now + tx_flush_interval;

    ovs_assert(pmd->n_output_batches > 0);
    pmd->n_output_batches--;

    pmd_perf_update_counter(&pmd->perf_stats, PMD_STAT_SENT_PKTS, output_cnt);
    pmd_perf_update_counter(&pmd->perf_stats, PMD_STAT_SENT_BATCHES, 1);

    /* Distribute send cycles evenly among transmitted packets and assign to
     * their respective rx queues. */
    cycles = cycle_timer_stop(&pmd->perf_stats, &timer) / output_cnt;
    for (i = 0; i < output_cnt; i++) {
        if (p->output_pkts_rxqs[i]) {
            dp_netdev_rxq_add_cycles(p->output_pkts_rxqs[i],
                                     RXQ_CYCLES_PROC_CURR, cycles);
        }
    }

    return output_cnt;
}

static int
dp_netdev_pmd_flush_output_packets(struct dp_netdev_pmd_thread *pmd,
                                   bool force)
{
    struct tx_port *p;
    int output_cnt = 0;

    if (!pmd->n_output_batches) {
        return 0;
    }

    HMAP_FOR_EACH (p, node, &pmd->send_port_cache) {
        if (!dp_packet_batch_is_empty(&p->output_pkts)
            && (force || pmd->ctx.now >= p->flush_time)) {
            output_cnt += dp_netdev_pmd_flush_output_on_port(pmd, p);
        }
    }
    return output_cnt;
}

//自队列中收取报文，并进行处理
static int
dp_netdev_process_rxq_port(struct dp_netdev_pmd_thread *pmd,
                           struct dp_netdev_rxq *rxq,
                           odp_port_t port_no)
{
    struct pmd_perf_stats *s = &pmd->perf_stats;
    struct dp_packet_batch batch;
    struct cycle_timer timer;
    int error;
    int batch_cnt = 0;
    int rem_qlen = 0, *qlen_p = NULL;
    uint64_t cycles;

    /* Measure duration for polling and processing rx burst. */
    cycle_timer_start(&pmd->perf_stats, &timer);

    pmd->ctx.last_rxq = rxq;
    dp_packet_batch_init(&batch);

    /* Fetch the rx queue length only for vhostuser ports. */
    if (pmd_perf_metrics_enabled(pmd) && rxq->is_vhost) {
        qlen_p = &rem_qlen;
    }

    //从队列中收包
    error = netdev_rxq_recv(rxq->rx, &batch, qlen_p);
    if (!error) {
        /* At least one packet received. */
        *recirc_depth_get() = 0;
        pmd_thread_ctx_time_update(pmd);
        batch_cnt = dp_packet_batch_size(&batch);
        if (pmd_perf_metrics_enabled(pmd)) {
            /* Update batch histogram. */
            s->current.batches++;
            histogram_add_sample(&s->pkts_per_batch, batch_cnt);
            /* Update the maximum vhost rx queue fill level. */
            if (rxq->is_vhost && rem_qlen >= 0) {
                uint32_t qfill = batch_cnt + rem_qlen;
                if (qfill > s->current.max_vhost_qfill) {
                    s->current.max_vhost_qfill = qfill;
                }
            }
        }
        /* Process packet batch. */
        //报文处理入口
        dp_netdev_input(pmd, &batch, port_no);

        /* Assign processing cycles to rx queue. */
        cycles = cycle_timer_stop(&pmd->perf_stats, &timer);
        dp_netdev_rxq_add_cycles(rxq, RXQ_CYCLES_PROC_CURR, cycles);

        dp_netdev_pmd_flush_output_packets(pmd, false);
    } else {
        /* Discard cycles. */
        cycle_timer_stop(&pmd->perf_stats, &timer);
        //收到其它非EAGAIN的错误，打错误日志
        if (error != EAGAIN && error != EOPNOTSUPP) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

            VLOG_ERR_RL(&rl, "error receiving data from %s: %s",
                    netdev_rxq_get_name(rxq->rx), ovs_strerror(error));
        }
    }

    pmd->ctx.last_rxq = NULL;

    return batch_cnt;
}

//给出port编号，获得此port对应的tx_port结构
static struct tx_port *
tx_port_lookup(const struct hmap *hmap, odp_port_t port_no)
{
    struct tx_port *tx;

    HMAP_FOR_EACH_IN_BUCKET (tx, node, hash_port_no(port_no), hmap) {
        if (tx->port->port_no == port_no) {
            return tx;
        }
    }

    return NULL;
}

//重配配置port(mtu,收队列，发队列等）
static int
port_reconfigure(struct dp_netdev_port *port)
{
    struct netdev *netdev = port->netdev;
    int i, err;

    /* Closes the existing 'rxq's. */
    //先释放掉当前port上所有存在的收队列
    for (i = 0; i < port->n_rxq; i++) {
        netdev_rxq_close(port->rxqs[i].rx);
        port->rxqs[i].rx = NULL;
    }

    unsigned last_nrxq = port->n_rxq;
    port->n_rxq = 0;

    /* Allows 'netdev' to apply the pending configuration changes. */
    if (netdev_is_reconf_required(netdev) || port->need_reconfigure) {
    	//使netdev生效
        err = netdev_reconfigure(netdev);
        if (err && (err != EOPNOTSUPP)) {
            VLOG_ERR("Failed to set interface %s new configuration",
                     netdev_get_name(netdev));
            return err;
        }
    }
    /* If the netdev_reconfigure() above succeeds, reopens the 'rxq's. */
    //重新按要求的数量创建rxq
    port->rxqs = xrealloc(port->rxqs,
                          sizeof *port->rxqs * netdev_n_rxq(netdev));
    /* Realloc 'used' counters for tx queues. */
    free(port->txq_used);
    port->txq_used = xcalloc(netdev_n_txq(netdev), sizeof *port->txq_used);

    //构造足够数量的收队列
    for (i = 0; i < netdev_n_rxq(netdev); i++) {
        bool new_queue = i >= last_nrxq;
        if (new_queue) {
            memset(&port->rxqs[i], 0, sizeof port->rxqs[i]);
        }

        port->rxqs[i].port = port;
        port->rxqs[i].is_vhost = !strncmp(port->type, "dpdkvhost", 9);

        err = netdev_rxq_open(netdev, &port->rxqs[i].rx, i);
        if (err) {
            return err;
        }
        port->n_rxq++;
    }

    /* Parse affinity list to apply configuration for new queues. */
    dpif_netdev_port_set_rxq_affinity(port, port->rxq_affinity_list);

    /* If reconfiguration was successful mark it as such, so we can use it */
    port->need_reconfigure = false;

    return 0;
}

struct rr_numa_list {
    struct hmap numas;  /* Contains 'struct rr_numa' */
};

struct rr_numa {
    struct hmap_node node;

    int numa_id;//numa节点id号

    /* Non isolated pmds on numa node 'numa_id' */
    struct dp_netdev_pmd_thread **pmds;//在此numa中的pmd引用（数组）
    int n_pmds;//有多少个pmd（数组长度）

    int cur_index;
    bool idx_inc;
};

static struct rr_numa *
rr_numa_list_lookup(struct rr_numa_list *rr, int numa_id)
{
    struct rr_numa *numa;

    HMAP_FOR_EACH_WITH_HASH (numa, node, hash_int(numa_id, 0), &rr->numas) {
        if (numa->numa_id == numa_id) {
            return numa;
        }
    }

    return NULL;
}

/* Returns the next node in numa list following 'numa' in round-robin fashion.
 * Returns first node if 'numa' is a null pointer or the last node in 'rr'.
 * Returns NULL if 'rr' numa list is empty. */
static struct rr_numa *
rr_numa_list_next(struct rr_numa_list *rr, const struct rr_numa *numa)
{
    struct hmap_node *node = NULL;

    if (numa) {
        node = hmap_next(&rr->numas, &numa->node);
    }
    if (!node) {
        node = hmap_first(&rr->numas);
    }

    return (node) ? CONTAINER_OF(node, struct rr_numa, node) : NULL;
}

//将所有未绑定core或者没有被隔离的pmd线程，按numa分类，并将其记录在rr中
static void
rr_numa_list_populate(struct dp_netdev *dp, struct rr_numa_list *rr)
{
    struct dp_netdev_pmd_thread *pmd;
    struct rr_numa *numa;

    hmap_init(&rr->numas);

    //将所有未绑定core或者没有被隔离的pmd线程，按numa分类，并将其记录在rr中
    CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
        //跳过已被隔离的pmd或者跳过没有绑定core的pmd
    	if (pmd->core_id == NON_PMD_CORE_ID || pmd->isolated) {
            continue;
        }

        numa = rr_numa_list_lookup(rr, pmd->numa_id);
        if (!numa) {
            numa = xzalloc(sizeof *numa);
            numa->numa_id = pmd->numa_id;
            hmap_insert(&rr->numas, &numa->node, hash_int(pmd->numa_id, 0));
        }
        numa->n_pmds++;
        numa->pmds = xrealloc(numa->pmds, numa->n_pmds * sizeof *numa->pmds);
        numa->pmds[numa->n_pmds - 1] = pmd;//存入当前pmd
        /* At least one pmd so initialise curr_idx and idx_inc. */
        numa->cur_index = 0;
        numa->idx_inc = true;
    }
}

/*
 * Returns the next pmd from the numa node.
 *
 * If 'updown' is 'true' it will alternate between selecting the next pmd in
 * either an up or down walk, switching between up/down when the first or last
 * core is reached. e.g. 1,2,3,3,2,1,1,2...
 *
 * If 'updown' is 'false' it will select the next pmd wrapping around when last
 * core reached. e.g. 1,2,3,1,2,3,1,2...
 */
static struct dp_netdev_pmd_thread *
rr_numa_get_pmd(struct rr_numa *numa, bool updown)
{
    int numa_idx = numa->cur_index;

    if (numa->idx_inc == true) {
        /* Incrementing through list of pmds. */
        if (numa->cur_index == numa->n_pmds-1) {
            /* Reached the last pmd. */
            if (updown) {
                numa->idx_inc = false;
            } else {
                numa->cur_index = 0;
            }
        } else {
            numa->cur_index++;
        }
    } else {
        /* Decrementing through list of pmds. */
        if (numa->cur_index == 0) {
            /* Reached the first pmd. */
            numa->idx_inc = true;
        } else {
            numa->cur_index--;
        }
    }
    return numa->pmds[numa_idx];
}

static void
rr_numa_list_destroy(struct rr_numa_list *rr)
{
    struct rr_numa *numa;

    HMAP_FOR_EACH_POP (numa, node, &rr->numas) {
        free(numa->pmds);
        free(numa);
    }
    hmap_destroy(&rr->numas);
}

/* Sort Rx Queues by the processing cycles they are consuming. */
static int
compare_rxq_cycles(const void *a, const void *b)
{
    struct dp_netdev_rxq *qa;
    struct dp_netdev_rxq *qb;
    uint64_t cycles_qa, cycles_qb;

    qa = *(struct dp_netdev_rxq **) a;
    qb = *(struct dp_netdev_rxq **) b;

    cycles_qa = dp_netdev_rxq_get_cycles(qa, RXQ_CYCLES_PROC_HIST);
    cycles_qb = dp_netdev_rxq_get_cycles(qb, RXQ_CYCLES_PROC_HIST);

    if (cycles_qa != cycles_qb) {
        return (cycles_qa < cycles_qb) ? 1 : -1;
    } else {
        /* Cycles are the same so tiebreak on port/queue id.
         * Tiebreaking (as opposed to return 0) ensures consistent
         * sort results across multiple OS's. */
        uint32_t port_qa = odp_to_u32(qa->port->port_no);
        uint32_t port_qb = odp_to_u32(qb->port->port_no);
        if (port_qa != port_qb) {
            return port_qa > port_qb ? 1 : -1;
        } else {
            return netdev_rxq_get_queue_id(qa->rx)
                    - netdev_rxq_get_queue_id(qb->rx);
        }
    }
}

/* Assign pmds to queues.  If 'pinned' is true, assign pmds to pinned
 * queues and marks the pmds as isolated.  Otherwise, assign non isolated
 * pmds to unpinned queues.
 *
 * The function doesn't touch the pmd threads, it just stores the assignment
 * in the 'pmd' member of each rxq. */
//rxq调度比较简单，分两种情况：
//1.先调度明确要求绑定的port,按其要求的core进行绑定.绑定后，此core设置为隔离
//2。接着调度没明确要求绑定的port,在调度前，会重新排除掉已被隔离的pmd(故一旦pmd被隔离，将不会自动有
//队列调度上来，需要手动绑定来指定），然后将与队列轮转的放在同一个numa上的所有pmd上。（如这次放1，下次放2）
static void
rxq_scheduling(struct dp_netdev *dp, bool pinned) OVS_REQUIRES(dp->port_mutex)
{
    struct dp_netdev_port *port;
    struct rr_numa_list rr;
    struct rr_numa *non_local_numa = NULL;
    struct dp_netdev_rxq ** rxqs = NULL;
    int n_rxqs = 0;
    struct rr_numa *numa = NULL;
    int numa_id;
    bool assign_cyc = dp->pmd_rxq_assign_cyc;

    //遍历dp的所有port
    HMAP_FOR_EACH (port, node, &dp->ports) {
        //不考虑非pmd的port(非pmd的绑定在0上）
        if (!netdev_is_pmd(port->netdev)) {
            continue;
        }

        //遍历此port的所有队列
        for (int qid = 0; qid < port->n_rxq; qid++) {
            struct dp_netdev_rxq *q = &port->rxqs[qid];

            //开启明确绑定，如果q要求绑定到某core
            if (pinned && q->core_id != OVS_CORE_UNSPEC) {
                struct dp_netdev_pmd_thread *pmd;

                //取出此core对应的pmd
                pmd = dp_netdev_get_pmd(dp, q->core_id);
                if (!pmd) {
                    //此core没有对应的pmd,warn,指明端口不会被poll
                	VLOG_WARN("There is no PMD thread on core %d. Queue "
                              "%d on port \'%s\' will not be polled.",
                              q->core_id, qid, netdev_get_name(port->netdev));
                } else {
                    q->pmd = pmd;
                    pmd->isolated = true;//指明独占（配置明确指明在此core上，不再接受自动配置）
                    dp_netdev_pmd_unref(pmd);
                }
            } else if (!pinned && q->core_id == OVS_CORE_UNSPEC) {
                uint64_t cycle_hist = 0;

                if (n_rxqs == 0) {
                    rxqs = xmalloc(sizeof *rxqs);
                } else {
                    rxqs = xrealloc(rxqs, sizeof *rxqs * (n_rxqs + 1));
                }

                if (assign_cyc) {
                    /* Sum the queue intervals and store the cycle history. */
                    for (unsigned i = 0; i < PMD_RXQ_INTERVAL_MAX; i++) {
                        cycle_hist += dp_netdev_rxq_get_intrvl_cycles(q, i);
                    }
                    dp_netdev_rxq_set_cycles(q, RXQ_CYCLES_PROC_HIST,
                                             cycle_hist);
                }
                /* Store the queue. */
                rxqs[n_rxqs++] = q;
            }
        }
    }

    if (n_rxqs > 1 && assign_cyc) {
        /* Sort the queues in order of the processing cycles
         * they consumed during their last pmd interval. */
        qsort(rxqs, n_rxqs, sizeof *rxqs, compare_rxq_cycles);
    }

    rr_numa_list_populate(dp, &rr);
    /* Assign the sorted queues to pmds in round robin. */
    for (int i = 0; i < n_rxqs; i++) {
        numa_id = netdev_get_numa_id(rxqs[i]->port->netdev);
        numa = rr_numa_list_lookup(&rr, numa_id);
        if (!numa) {
            /* There are no pmds on the queue's local NUMA node.
               Round robin on the NUMA nodes that do have pmds. */
            non_local_numa = rr_numa_list_next(&rr, non_local_numa);
            if (!non_local_numa) {
                VLOG_ERR("There is no available (non-isolated) pmd "
                         "thread for port \'%s\' queue %d. This queue "
                         "will not be polled. Is pmd-cpu-mask set to "
                         "zero? Or are all PMDs isolated to other "
                         "queues?", netdev_rxq_get_name(rxqs[i]->rx),
                         netdev_rxq_get_queue_id(rxqs[i]->rx));
                continue;
            }
            rxqs[i]->pmd = rr_numa_get_pmd(non_local_numa, assign_cyc);
            VLOG_WARN("There's no available (non-isolated) pmd thread "
                      "on numa node %d. Queue %d on port \'%s\' will "
                      "be assigned to the pmd on core %d "
                      "(numa node %d). Expect reduced performance.",
                      numa_id, netdev_rxq_get_queue_id(rxqs[i]->rx),
                      netdev_rxq_get_name(rxqs[i]->rx),
                      rxqs[i]->pmd->core_id, rxqs[i]->pmd->numa_id);
        } else {
            rxqs[i]->pmd = rr_numa_get_pmd(numa, assign_cyc);
            if (assign_cyc) {
                VLOG_INFO("Core %d on numa node %d assigned port \'%s\' "
                          "rx queue %d "
                          "(measured processing cycles %"PRIu64").",
                          rxqs[i]->pmd->core_id, numa_id,
                          netdev_rxq_get_name(rxqs[i]->rx),
                          netdev_rxq_get_queue_id(rxqs[i]->rx),
                          dp_netdev_rxq_get_cycles(rxqs[i],
                                                   RXQ_CYCLES_PROC_HIST));
            } else {
                VLOG_INFO("Core %d on numa node %d assigned port \'%s\' "
                          "rx queue %d.", rxqs[i]->pmd->core_id, numa_id,
                          netdev_rxq_get_name(rxqs[i]->rx),
                          netdev_rxq_get_queue_id(rxqs[i]->rx));
            }
        }
    }

    //销毁临时结构
    rr_numa_list_destroy(&rr);
    free(rxqs);
}

static void
reload_affected_pmds(struct dp_netdev *dp)
{
    struct dp_netdev_pmd_thread *pmd;

    CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
        if (pmd->need_reload) {
            flow_mark_flush(pmd);
            dp_netdev_reload_pmd__(pmd);
        }
    }

    CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
        if (pmd->need_reload) {
            if (pmd->core_id != NON_PMD_CORE_ID) {
                bool reload;

                do {
                    atomic_read_explicit(&pmd->reload, &reload,
                                         memory_order_acquire);
                } while (reload);
            }
            pmd->need_reload = false;
        }
    }
}

static void
reconfigure_pmd_threads(struct dp_netdev *dp)
    OVS_REQUIRES(dp->port_mutex)
{
    struct dp_netdev_pmd_thread *pmd;
    struct ovs_numa_dump *pmd_cores;
    struct ovs_numa_info_core *core;
    struct hmapx to_delete = HMAPX_INITIALIZER(&to_delete);
    struct hmapx_node *node;
    bool changed = false;
    bool need_to_adjust_static_tx_qids = false;

    /* The pmd threads should be started only if there's a pmd port in the
     * datapath.  If the user didn't provide any "pmd-cpu-mask", we start
     * NR_PMD_THREADS per numa node. */
    if (!has_pmd_port(dp)) {
        //dp里没有pmd port
    	pmd_cores = ovs_numa_dump_n_cores_per_numa(0);//每个numa上取0个（即返回空集）
    } else if (dp->pmd_cmask && dp->pmd_cmask[0]) {
        //配置了pmd_cmask
    	pmd_cores = ovs_numa_dump_cores_with_cmask(dp->pmd_cmask);
    } else {
        pmd_cores = ovs_numa_dump_n_cores_per_numa(NR_PMD_THREADS);//每个numa上取1个
    }

    /* We need to adjust 'static_tx_qid's only if we're reducing number of
     * PMD threads. Otherwise, new threads will allocate all the freed ids. */
    if (ovs_numa_dump_count(pmd_cores) < cmap_count(&dp->poll_threads) - 1) {
        /* Adjustment is required to keep 'static_tx_qid's sequential and
         * avoid possible issues, for example, imbalanced tx queue usage
         * and unnecessary locking caused by remapping on netdev level. */
        need_to_adjust_static_tx_qids = true;
    }

    /* Check for unwanted pmd threads */
    CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
        if (pmd->core_id == NON_PMD_CORE_ID) {
            continue;
        }
        if (!ovs_numa_dump_contains_core(pmd_cores, pmd->numa_id,
                                                    pmd->core_id)) {
            hmapx_add(&to_delete, pmd);
        } else if (need_to_adjust_static_tx_qids) {
            atomic_store_relaxed(&pmd->reload_tx_qid, true);
            pmd->need_reload = true;
        }
    }

    HMAPX_FOR_EACH (node, &to_delete) {
        pmd = (struct dp_netdev_pmd_thread *) node->data;
        VLOG_INFO("PMD thread on numa_id: %d, core id: %2d destroyed.",
                  pmd->numa_id, pmd->core_id);
        dp_netdev_del_pmd(dp, pmd);
    }
    changed = !hmapx_is_empty(&to_delete);
    hmapx_destroy(&to_delete);

    if (need_to_adjust_static_tx_qids) {
        /* 'static_tx_qid's are not sequential now.
         * Reload remaining threads to fix this. */
        reload_affected_pmds(dp);
    }

    /* Check for required new pmd threads */
    FOR_EACH_CORE_ON_DUMP(core, pmd_cores) {
        pmd = dp_netdev_get_pmd(dp, core->core_id);
        if (!pmd) {
            struct ds name = DS_EMPTY_INITIALIZER;

            pmd = xzalloc(sizeof *pmd);
            dp_netdev_configure_pmd(pmd, dp, core->core_id, core->numa_id);

            ds_put_format(&name, "pmd-c%02d/id:", core->core_id);
            pmd->thread = ovs_thread_create(ds_cstr(&name),
                                            pmd_thread_main, pmd);
            ds_destroy(&name);

            VLOG_INFO("PMD thread on numa_id: %d, core id: %2d created.",
                      pmd->numa_id, pmd->core_id);
            changed = true;
        } else {
            dp_netdev_pmd_unref(pmd);
        }
    }

    if (changed) {
        struct ovs_numa_info_numa *numa;

        /* Log the number of pmd threads per numa node. */
        FOR_EACH_NUMA_ON_DUMP (numa, pmd_cores) {
            VLOG_INFO("There are %"PRIuSIZE" pmd threads on numa node %d",
                      numa->n_cores, numa->numa_id);
        }
    }

    ovs_numa_dump_destroy(pmd_cores);//销毁临时变量
}

//在给定的pmd中检查dp的所有ports，如果有port已不存在
//或者port需要重新配置，则自pmd中移除
static void
pmd_remove_stale_ports(struct dp_netdev *dp,
                       struct dp_netdev_pmd_thread *pmd)
    OVS_EXCLUDED(pmd->port_mutex)
    OVS_REQUIRES(dp->port_mutex)
{
    struct rxq_poll *poll, *poll_next;
    struct tx_port *tx, *tx_next;

    ovs_mutex_lock(&pmd->port_mutex);
    //检查收情况
    HMAP_FOR_EACH_SAFE (poll, poll_next, node, &pmd->poll_list) {
        struct dp_netdev_port *port = poll->rxq->port;

        //dp中不存在此port了，将其删除
        if (port->need_reconfigure
            || !hmap_contains(&dp->ports, &port->node)) {
            dp_netdev_del_rxq_from_pmd(pmd, poll);
        }
    }

    //检查发情况
    HMAP_FOR_EACH_SAFE (tx, tx_next, node, &pmd->tx_ports) {
        struct dp_netdev_port *port = tx->port;

        //dp中不存在此port了，将其删除
        if (port->need_reconfigure
            || !hmap_contains(&dp->ports, &port->node)) {
            dp_netdev_del_port_tx_from_pmd(pmd, tx);
        }
    }
    ovs_mutex_unlock(&pmd->port_mutex);
}

/* Must be called each time a port is added/removed or the cmask changes.
 * This creates and destroys pmd threads, reconfigures ports, opens their
 * rxqs and assigns all rxqs/txqs to pmd threads. */
static void
reconfigure_datapath(struct dp_netdev *dp)
    OVS_REQUIRES(dp->port_mutex)
{
    struct hmapx busy_threads = HMAPX_INITIALIZER(&busy_threads);
    struct dp_netdev_pmd_thread *pmd;
    struct dp_netdev_port *port;
    int wanted_txqs;

    //更新我们的序列号
    dp->last_reconfigure_seq = seq_read(dp->reconfigure_seq);

    /* Step 1: Adjust the pmd threads based on the datapath ports, the cores
     * on the system and the user configuration. */
    reconfigure_pmd_threads(dp);//重新配置pmd线程配置

    wanted_txqs = cmap_count(&dp->poll_threads);//pmd线程数

    /* The number of pmd threads might have changed, or a port can be new:
     * adjust the txqs. */
    //pmd线程数量已确定，由于每个pmd均需要发任何一个port,故dp上每个port
    //均需要支持有wantd_txqs个队列来解决这一要求。注为了保证配置一致性，此函数不立即生效。
    HMAP_FOR_EACH (port, node, &dp->ports) {
        netdev_set_tx_multiq(port->netdev, wanted_txqs);
    }

    /* Step 2: Remove from the pmd threads ports that have been removed or
     * need reconfiguration. */

    /* Check for all the ports that need reconfiguration.  We cache this in
     * 'port->need_reconfigure', because netdev_is_reconf_required() can
     * change at any time. */
    //检查是否有port的netdev需要重新配置，例如上面有发送队列数量变更
    HMAP_FOR_EACH (port, node, &dp->ports) {
        if (netdev_is_reconf_required(port->netdev)) {
            port->need_reconfigure = true;
        }
    }

    /* Remove from the pmd threads all the ports that have been deleted or
     * need reconfiguration. */
    //有些port在pmd中不存在了，需要将其移除掉
    CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
        pmd_remove_stale_ports(dp, pmd);
    }

    /* Reload affected pmd threads.  We must wait for the pmd threads before
     * reconfiguring the ports, because a port cannot be reconfigured while
     * it's being used. */
    //同步点，等待受影响的pmds完成reload
    //在重新配置port前,pmd中需要先移除掉无用port，故使pmd执行reload
    reload_affected_pmds(dp);

    /* Step 3: Reconfigure ports. */

    /* We only reconfigure the ports that we determined above, because they're
     * not being used by any pmd thread at the moment.  If a port fails to
     * reconfigure we remove it from the datapath. */
	//使port进行重配置
    struct dp_netdev_port *next_port;
    HMAP_FOR_EACH_SAFE (port, next_port, node, &dp->ports) {
        int err;

        if (!port->need_reconfigure) {
        	//不需要配置，跳过
            continue;
        }

        //如果重新配置port失败，则此port将自dp中移除
        err = port_reconfigure(port);
        if (err) {
        	//将失败的port自datapath中移除掉
            hmap_remove(&dp->ports, &port->node);
            seq_change(dp->port_seq);
            port_destroy(port);
        } else {
            port->dynamic_txqs = netdev_n_txq(port->netdev) < wanted_txqs;
        }
    }

    /* Step 4: Compute new rxq scheduling.  We don't touch the pmd threads
     * for now, we just update the 'pmd' pointer in each rxq to point to the
     * wanted thread according to the scheduling policy. */

    /* Reset all the pmd threads to non isolated. */
    //将所有pmd线程置为不隔离
    CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
        pmd->isolated = false;
    }

    /* Reset all the queues to unassigned */
    //置各rxq对应的pmd为NULL
    HMAP_FOR_EACH (port, node, &dp->ports) {
        for (int i = 0; i < port->n_rxq; i++) {
            port->rxqs[i].pmd = NULL;
        }
    }

    //队列调度
    /* Add pinned queues and mark pmd threads isolated. */
    rxq_scheduling(dp, true);

    /* Add non-pinned queues. */
    rxq_scheduling(dp, false);

    /* Step 5: Remove queues not compliant with new scheduling. */

    /* Count all the threads that will have at least one queue to poll. */
    HMAP_FOR_EACH (port, node, &dp->ports) {
        for (int qid = 0; qid < port->n_rxq; qid++) {
            struct dp_netdev_rxq *q = &port->rxqs[qid];

            if (q->pmd) {
                hmapx_add(&busy_threads, q->pmd);
            }
        }
    }

    //遍历所有pmd，将其不再负责的队列自pmd的poll_list中移除,  使其不再poll
    CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
        struct rxq_poll *poll, *poll_next;

        ovs_mutex_lock(&pmd->port_mutex);
        HMAP_FOR_EACH_SAFE (poll, poll_next, node, &pmd->poll_list) {
            //rxq_scheduling函数中可能将此队列放在别的pmd上了，故需要移除
        	if (poll->rxq->pmd != pmd) {
                dp_netdev_del_rxq_from_pmd(pmd, poll);

                /* This pmd might sleep after this step if it has no rxq
                 * remaining. Tell it to busy wait for new assignment if it
                 * has at least one scheduled queue. */
                if (hmap_count(&pmd->poll_list) == 0 &&
                    hmapx_contains(&busy_threads, pmd)) {
                    atomic_store_relaxed(&pmd->wait_for_reload, true);
                }
            }
        }
        ovs_mutex_unlock(&pmd->port_mutex);
    }

    hmapx_destroy(&busy_threads);

    /* Reload affected pmd threads.  We must wait for the pmd threads to remove
     * the old queues before readding them, otherwise a queue can be polled by
     * two threads at the same time. */
    reload_affected_pmds(dp);//使pmd重新load

    /* Step 6: Add queues from scheduling, if they're not there already. */
    //第5步，我们移除了不再由pmd负责的队列，但有一些新加入的对队还没有加入到pmd中，这里将其加入。
    HMAP_FOR_EACH (port, node, &dp->ports) {
        //忽略非pmd设备
    	if (!netdev_is_pmd(port->netdev)) {
            continue;
        }

    	//遍历当前port上的所有队列
        for (int qid = 0; qid < port->n_rxq; qid++) {
            struct dp_netdev_rxq *q = &port->rxqs[qid];

            //如果队列有所属的pmd，则将队列加入所属的pmd
            if (q->pmd) {
                ovs_mutex_lock(&q->pmd->port_mutex);
                dp_netdev_add_rxq_to_pmd(q->pmd, q);//将此队列加入到对应的pmd中，用于轮询
                ovs_mutex_unlock(&q->pmd->port_mutex);
            }
        }
    }

    /* Add every port to the tx cache of every pmd thread, if it's not
     * there already and if this pmd has at least one rxq to poll. */
    //将dp中的所有port加入到dp的每个pmd发送中
    CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
        ovs_mutex_lock(&pmd->port_mutex);
        if (hmap_count(&pmd->poll_list) || pmd->core_id == NON_PMD_CORE_ID) {
            HMAP_FOR_EACH (port, node, &dp->ports) {
                //使dp中的每一个ports均可被pmd发送（包含隧道口）
            		dp_netdev_add_port_tx_to_pmd(pmd, port);
            }
        }
        ovs_mutex_unlock(&pmd->port_mutex);
    }

    /* Reload affected pmd threads. */
    reload_affected_pmds(dp);

    /* Check if PMD Auto LB is to be enabled */
    set_pmd_auto_lb(dp);
}

/* Returns true if one of the netdevs in 'dp' requires a reconfiguration */
//检查dp上是否存在某port要求重启配置，如果有返回True,否则False
static bool
ports_require_restart(const struct dp_netdev *dp)
    OVS_REQUIRES(dp->port_mutex)
{
    struct dp_netdev_port *port;

    HMAP_FOR_EACH (port, node, &dp->ports) {
        if (netdev_is_reconf_required(port->netdev)) {
            return true;
        }
    }

    return false;
}

/* Calculates variance in the values stored in array 'a'. 'n' is the number
 * of elements in array to be considered for calculating vairance.
 * Usage example: data array 'a' contains the processing load of each pmd and
 * 'n' is the number of PMDs. It returns the variance in processing load of
 * PMDs*/
static uint64_t
variance(uint64_t a[], int n)
{
    /* Compute mean (average of elements). */
    uint64_t sum = 0;
    uint64_t mean = 0;
    uint64_t sqDiff = 0;

    if (!n) {
        return 0;
    }

    for (int i = 0; i < n; i++) {
        sum += a[i];
    }

    if (sum) {
        mean = sum / n;

        /* Compute sum squared differences with mean. */
        for (int i = 0; i < n; i++) {
            sqDiff += (a[i] - mean)*(a[i] - mean);
        }
    }
    return (sqDiff ? (sqDiff / n) : 0);
}


/* Returns the variance in the PMDs usage as part of dry run of rxqs
 * assignment to PMDs. */
static bool
get_dry_run_variance(struct dp_netdev *dp, uint32_t *core_list,
                     uint32_t num_pmds, uint64_t *predicted_variance)
    OVS_REQUIRES(dp->port_mutex)
{
    struct dp_netdev_port *port;
    struct dp_netdev_pmd_thread *pmd;
    struct dp_netdev_rxq **rxqs = NULL;
    struct rr_numa *numa = NULL;
    struct rr_numa_list rr;
    int n_rxqs = 0;
    bool ret = false;
    uint64_t *pmd_usage;

    if (!predicted_variance) {
        return ret;
    }

    pmd_usage = xcalloc(num_pmds, sizeof(uint64_t));

    HMAP_FOR_EACH (port, node, &dp->ports) {
        if (!netdev_is_pmd(port->netdev)) {
            continue;
        }

        for (int qid = 0; qid < port->n_rxq; qid++) {
            struct dp_netdev_rxq *q = &port->rxqs[qid];
            uint64_t cycle_hist = 0;

            if (q->pmd->isolated) {
                continue;
            }

            if (n_rxqs == 0) {
                rxqs = xmalloc(sizeof *rxqs);
            } else {
                rxqs = xrealloc(rxqs, sizeof *rxqs * (n_rxqs + 1));
            }

            /* Sum the queue intervals and store the cycle history. */
            for (unsigned i = 0; i < PMD_RXQ_INTERVAL_MAX; i++) {
                cycle_hist += dp_netdev_rxq_get_intrvl_cycles(q, i);
            }
            dp_netdev_rxq_set_cycles(q, RXQ_CYCLES_PROC_HIST,
                                         cycle_hist);
            /* Store the queue. */
            rxqs[n_rxqs++] = q;
        }
    }
    if (n_rxqs > 1) {
        /* Sort the queues in order of the processing cycles
         * they consumed during their last pmd interval. */
        qsort(rxqs, n_rxqs, sizeof *rxqs, compare_rxq_cycles);
    }
    rr_numa_list_populate(dp, &rr);

    for (int i = 0; i < n_rxqs; i++) {
        int numa_id = netdev_get_numa_id(rxqs[i]->port->netdev);
        numa = rr_numa_list_lookup(&rr, numa_id);
        if (!numa) {
            /* Abort if cross NUMA polling. */
            VLOG_DBG("PMD auto lb dry run."
                     " Aborting due to cross-numa polling.");
            goto cleanup;
        }

        pmd = rr_numa_get_pmd(numa, true);
        VLOG_DBG("PMD auto lb dry run. Predicted: Core %d on numa node %d "
                  "to be assigned port \'%s\' rx queue %d "
                  "(measured processing cycles %"PRIu64").",
                  pmd->core_id, numa_id,
                  netdev_rxq_get_name(rxqs[i]->rx),
                  netdev_rxq_get_queue_id(rxqs[i]->rx),
                  dp_netdev_rxq_get_cycles(rxqs[i], RXQ_CYCLES_PROC_HIST));

        for (int id = 0; id < num_pmds; id++) {
            if (pmd->core_id == core_list[id]) {
                /* Add the processing cycles of rxq to pmd polling it. */
                pmd_usage[id] += dp_netdev_rxq_get_cycles(rxqs[i],
                                        RXQ_CYCLES_PROC_HIST);
            }
        }
    }

    CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
        uint64_t total_cycles = 0;

        if ((pmd->core_id == NON_PMD_CORE_ID) || pmd->isolated) {
            continue;
        }

        /* Get the total pmd cycles for an interval. */
        atomic_read_relaxed(&pmd->intrvl_cycles, &total_cycles);
        /* Estimate the cycles to cover all intervals. */
        total_cycles *= PMD_RXQ_INTERVAL_MAX;
        for (int id = 0; id < num_pmds; id++) {
            if (pmd->core_id == core_list[id]) {
                if (pmd_usage[id]) {
                    pmd_usage[id] = (pmd_usage[id] * 100) / total_cycles;
                }
                VLOG_DBG("PMD auto lb dry run. Predicted: Core %d, "
                         "usage %"PRIu64"", pmd->core_id, pmd_usage[id]);
            }
        }
    }
    *predicted_variance = variance(pmd_usage, num_pmds);
    ret = true;

cleanup:
    rr_numa_list_destroy(&rr);
    free(rxqs);
    free(pmd_usage);
    return ret;
}

/* Does the dry run of Rxq assignment to PMDs and returns true if it gives
 * better distribution of load on PMDs. */
static bool
pmd_rebalance_dry_run(struct dp_netdev *dp)
    OVS_REQUIRES(dp->port_mutex)
{
    struct dp_netdev_pmd_thread *pmd;
    uint64_t *curr_pmd_usage;

    uint64_t curr_variance;
    uint64_t new_variance;
    uint64_t improvement = 0;
    uint32_t num_pmds;
    uint32_t *pmd_corelist;
    struct rxq_poll *poll;
    bool ret;

    num_pmds = cmap_count(&dp->poll_threads);

    if (num_pmds > 1) {
        curr_pmd_usage = xcalloc(num_pmds, sizeof(uint64_t));
        pmd_corelist = xcalloc(num_pmds, sizeof(uint32_t));
    } else {
        return false;
    }

    num_pmds = 0;
    CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
        uint64_t total_cycles = 0;
        uint64_t total_proc = 0;

        if ((pmd->core_id == NON_PMD_CORE_ID) || pmd->isolated) {
            continue;
        }

        /* Get the total pmd cycles for an interval. */
        atomic_read_relaxed(&pmd->intrvl_cycles, &total_cycles);
        /* Estimate the cycles to cover all intervals. */
        total_cycles *= PMD_RXQ_INTERVAL_MAX;

        ovs_mutex_lock(&pmd->port_mutex);
        HMAP_FOR_EACH (poll, node, &pmd->poll_list) {
            for (unsigned i = 0; i < PMD_RXQ_INTERVAL_MAX; i++) {
                total_proc += dp_netdev_rxq_get_intrvl_cycles(poll->rxq, i);
            }
        }
        ovs_mutex_unlock(&pmd->port_mutex);

        if (total_proc) {
            curr_pmd_usage[num_pmds] = (total_proc * 100) / total_cycles;
        }

        VLOG_DBG("PMD auto lb dry run. Current: Core %d, usage %"PRIu64"",
                  pmd->core_id, curr_pmd_usage[num_pmds]);

        if (atomic_count_get(&pmd->pmd_overloaded)) {
            atomic_count_set(&pmd->pmd_overloaded, 0);
        }

        pmd_corelist[num_pmds] = pmd->core_id;
        num_pmds++;
    }

    curr_variance = variance(curr_pmd_usage, num_pmds);
    ret = get_dry_run_variance(dp, pmd_corelist, num_pmds, &new_variance);

    if (ret) {
        VLOG_DBG("PMD auto lb dry run. Current PMD variance: %"PRIu64","
                  " Predicted PMD variance: %"PRIu64"",
                  curr_variance, new_variance);

        if (new_variance < curr_variance) {
            improvement =
                ((curr_variance - new_variance) * 100) / curr_variance;
        }
        if (improvement < ALB_ACCEPTABLE_IMPROVEMENT) {
            ret = false;
        }
    }

    free(curr_pmd_usage);
    free(pmd_corelist);
    return ret;
}


/* Return true if needs to revalidate datapath flows. */
static bool
dpif_netdev_run(struct dpif *dpif)
{
    struct dp_netdev_port *port;
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_pmd_thread *non_pmd;
    uint64_t new_tnl_seq;
    bool need_to_flush = true;
    bool pmd_rebalance = false;
    long long int now = time_msec();
    struct dp_netdev_pmd_thread *pmd;

    ovs_mutex_lock(&dp->port_mutex);
    non_pmd = dp_netdev_get_pmd(dp, NON_PMD_CORE_ID);
    if (non_pmd) {
        ovs_mutex_lock(&dp->non_pmd_mutex);
        HMAP_FOR_EACH (port, node, &dp->ports) {
        	//自非pmd上进行收发包处理
            if (!netdev_is_pmd(port->netdev)) {
                int i;

                if (port->emc_enabled) {
                    atomic_read_relaxed(&dp->emc_insert_min,
                                        &non_pmd->ctx.emc_insert_min);
                } else {
                    non_pmd->ctx.emc_insert_min = 0;
                }

                for (i = 0; i < port->n_rxq; i++) {

                    if (!netdev_rxq_enabled(port->rxqs[i].rx)) {
                        continue;
                    }

                    if (dp_netdev_process_rxq_port(non_pmd,
                                                   &port->rxqs[i],
                                                   port->port_no)) {
                        need_to_flush = false;
                    }
                }
            }
        }
        if (need_to_flush) {
            /* We didn't receive anything in the process loop.
             * Check if we need to send something.
             * There was no time updates on current iteration. */
            pmd_thread_ctx_time_update(non_pmd);
            dp_netdev_pmd_flush_output_packets(non_pmd, false);
        }

        dpif_netdev_xps_revalidate_pmd(non_pmd, false);
        ovs_mutex_unlock(&dp->non_pmd_mutex);

        dp_netdev_pmd_unref(non_pmd);
    }

    struct pmd_auto_lb *pmd_alb = &dp->pmd_alb;
    if (pmd_alb->is_enabled) {
        if (!pmd_alb->rebalance_poll_timer) {
            pmd_alb->rebalance_poll_timer = now;
        } else if ((pmd_alb->rebalance_poll_timer +
                   pmd_alb->rebalance_intvl) < now) {
            pmd_alb->rebalance_poll_timer = now;
            CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
                if (atomic_count_get(&pmd->pmd_overloaded) >=
                                    PMD_RXQ_INTERVAL_MAX) {
                    pmd_rebalance = true;
                    break;
                }
            }

            if (pmd_rebalance &&
                !dp_netdev_is_reconf_required(dp) &&
                !ports_require_restart(dp) &&
                pmd_rebalance_dry_run(dp)) {
                VLOG_INFO("PMD auto lb dry run."
                          " requesting datapath reconfigure.");
                dp_netdev_request_reconfigure(dp);
            }
        }
    }

    //如果dp要求重配置或者dp中的port要求重配置，则进入重配置
    if (dp_netdev_is_reconf_required(dp) || ports_require_restart(dp)) {
        reconfigure_datapath(dp);
    }
    ovs_mutex_unlock(&dp->port_mutex);

    tnl_neigh_cache_run();
    tnl_port_map_run();
    new_tnl_seq = seq_read(tnl_conf_seq);

    if (dp->last_tnl_conf_seq != new_tnl_seq) {
        dp->last_tnl_conf_seq = new_tnl_seq;
        return true;
    }
    return false;
}

static void
dpif_netdev_wait(struct dpif *dpif)
{
    struct dp_netdev_port *port;
    struct dp_netdev *dp = get_dp_netdev(dpif);

    ovs_mutex_lock(&dp_netdev_mutex);
    ovs_mutex_lock(&dp->port_mutex);
    HMAP_FOR_EACH (port, node, &dp->ports) {
        netdev_wait_reconf_required(port->netdev);
        if (!netdev_is_pmd(port->netdev)) {
            int i;

            for (i = 0; i < port->n_rxq; i++) {
                netdev_rxq_wait(port->rxqs[i].rx);
            }
        }
    }
    ovs_mutex_unlock(&dp->port_mutex);
    ovs_mutex_unlock(&dp_netdev_mutex);
    seq_wait(tnl_conf_seq, dp->last_tnl_conf_seq);
}

static void
pmd_free_cached_ports(struct dp_netdev_pmd_thread *pmd)
{
    struct tx_port *tx_port_cached;

    /* Flush all the queued packets. */
    dp_netdev_pmd_flush_output_packets(pmd, true);
    /* Free all used tx queue ids. */
    dpif_netdev_xps_revalidate_pmd(pmd, true);

    HMAP_FOR_EACH_POP (tx_port_cached, node, &pmd->tnl_port_cache) {
        free(tx_port_cached);
    }
    HMAP_FOR_EACH_POP (tx_port_cached, node, &pmd->send_port_cache) {
        free(tx_port_cached);
    }
}

/* Copies ports from 'pmd->tx_ports' (shared with the main thread) to
 * thread-local copies. Copy to 'pmd->tnl_port_cache' if it is a tunnel
 * device, otherwise to 'pmd->send_port_cache' if the port has at least
 * one txq. */
static void
pmd_load_cached_ports(struct dp_netdev_pmd_thread *pmd)
    OVS_REQUIRES(pmd->port_mutex)
{
    struct tx_port *tx_port, *tx_port_cached;

    //先将tnl_port_cache,send_port_cache清空
    pmd_free_cached_ports(pmd);
    hmap_shrink(&pmd->send_port_cache);
    hmap_shrink(&pmd->tnl_port_cache);

    HMAP_FOR_EACH (tx_port, node, &pmd->tx_ports) {
        //将tx_ports中有push pop能力的netdev加入到tnl_port_cache
    		if (netdev_has_tunnel_push_pop(tx_port->port->netdev)) {
            tx_port_cached = xmemdup(tx_port, sizeof *tx_port_cached);
            hmap_insert(&pmd->tnl_port_cache, &tx_port_cached->node,
                        hash_port_no(tx_port_cached->port->port_no));
        }

    		//将tx_ports中有tx队列的port加入到send_port_cache
        if (netdev_n_txq(tx_port->port->netdev)) {
            tx_port_cached = xmemdup(tx_port, sizeof *tx_port_cached);
            hmap_insert(&pmd->send_port_cache, &tx_port_cached->node,
                        hash_port_no(tx_port_cached->port->port_no));
        }
    }
}

static void
pmd_alloc_static_tx_qid(struct dp_netdev_pmd_thread *pmd)
{
    ovs_mutex_lock(&pmd->dp->tx_qid_pool_mutex);
    if (!id_pool_alloc_id(pmd->dp->tx_qid_pool, &pmd->static_tx_qid)) {
        VLOG_ABORT("static_tx_qid allocation failed for PMD on core %2d"
                   ", numa_id %d.", pmd->core_id, pmd->numa_id);
    }
    ovs_mutex_unlock(&pmd->dp->tx_qid_pool_mutex);

    VLOG_DBG("static_tx_qid = %d allocated for PMD thread on core %2d"
             ", numa_id %d.", pmd->static_tx_qid, pmd->core_id, pmd->numa_id);
}

static void
pmd_free_static_tx_qid(struct dp_netdev_pmd_thread *pmd)
{
    ovs_mutex_lock(&pmd->dp->tx_qid_pool_mutex);
    id_pool_free_id(pmd->dp->tx_qid_pool, pmd->static_tx_qid);
    ovs_mutex_unlock(&pmd->dp->tx_qid_pool_mutex);
}

static int
pmd_load_queues_and_ports(struct dp_netdev_pmd_thread *pmd,
                          struct polled_queue **ppoll_list)
{
    struct polled_queue *poll_list = *ppoll_list;
    struct rxq_poll *poll;
    int i;

    ovs_mutex_lock(&pmd->port_mutex);
    poll_list = xrealloc(poll_list, hmap_count(&pmd->poll_list)
                                    * sizeof *poll_list);

    //收集当前pmd负责收取哪些队列
    i = 0;
    HMAP_FOR_EACH (poll, node, &pmd->poll_list) {
        poll_list[i].rxq = poll->rxq;
        poll_list[i].port_no = poll->rxq->port->port_no;
        poll_list[i].emc_enabled = poll->rxq->port->emc_enabled;
        poll_list[i].rxq_enabled = netdev_rxq_enabled(poll->rxq->rx);
        poll_list[i].change_seq =
                     netdev_get_change_seq(poll->rxq->port->netdev);
        i++;
    }

    pmd_load_cached_ports(pmd);

    ovs_mutex_unlock(&pmd->port_mutex);

    *ppoll_list = poll_list;
    return i;
}

//pmd线程任务函数
static void *
pmd_thread_main(void *f_)
{
    struct dp_netdev_pmd_thread *pmd = f_;
    struct pmd_perf_stats *s = &pmd->perf_stats;
    unsigned int lc = 0;
    struct polled_queue *poll_list;
    bool wait_for_reload = false;
    bool reload_tx_qid;
    bool exiting;
    bool reload;
    int poll_cnt;
    int i;
    int process_packets = 0;

    poll_list = NULL;

    /* Stores the pmd thread's 'pmd' to 'per_pmd_key'. */
    ovsthread_setspecific(pmd->dp->per_pmd_key, pmd);
    ovs_numa_thread_setaffinity_core(pmd->core_id);//为线程绑定core
    dpdk_set_lcore_id(pmd->core_id);//为了保证dpdk收发包，设置dpdk需要的core信息
    poll_cnt = pmd_load_queues_and_ports(pmd, &poll_list);//线程创建后已加入我们需要负责哪些port
    dfc_cache_init(&pmd->flow_cache);//emc cache初始化
    pmd_alloc_static_tx_qid(pmd);

reload:
    atomic_count_init(&pmd->pmd_overloaded, 0);

    /* List port/core affinity */
    for (i = 0; i < poll_cnt; i++) {
       VLOG_DBG("Core %d processing port \'%s\' with queue-id %d\n",
                pmd->core_id, netdev_rxq_get_name(poll_list[i].rxq->rx),
                netdev_rxq_get_queue_id(poll_list[i].rxq->rx));
       /* Reset the rxq current cycles counter. */
       dp_netdev_rxq_set_cycles(poll_list[i].rxq, RXQ_CYCLES_PROC_CURR, 0);
    }

    if (!poll_cnt) {
        if (wait_for_reload) {
            /* Don't sleep, control thread will ask for a reload shortly. */
            do {
                atomic_read_explicit(&pmd->reload, &reload,
                                     memory_order_acquire);
            } while (!reload);
        } else {
            //我们没有要负责的port,阻塞等待
            while (seq_read(pmd->reload_seq) == pmd->last_reload_seq) {
                seq_wait(pmd->reload_seq, pmd->last_reload_seq);
                poll_block();
            }
        }
    }

    pmd->intrvl_tsc_prev = 0;
    atomic_store_relaxed(&pmd->intrvl_cycles, 0);
    cycles_counter_update(s);
    /* Protect pmd stats from external clearing while polling. */
    ovs_mutex_lock(&pmd->perf_stats.stats_mutex);
    //主循环，处理报文
    for (;;) {
        uint64_t rx_packets = 0, tx_packets = 0;

        pmd_perf_start_iteration(s);

        for (i = 0; i < poll_cnt; i++) {

            if (!poll_list[i].rxq_enabled) {
                continue;
            }

            if (poll_list[i].emc_enabled) {
                atomic_read_relaxed(&pmd->dp->emc_insert_min,
                                    &pmd->ctx.emc_insert_min);
            } else {
                pmd->ctx.emc_insert_min = 0;
            }

            //对我们负责的port进行收发包处理
            process_packets =
                dp_netdev_process_rxq_port(pmd, poll_list[i].rxq,
                                           poll_list[i].port_no);
            rx_packets += process_packets;
        }

        if (!rx_packets) {
            /* We didn't receive anything in the process loop.
             * Check if we need to send something.
             * There was no time updates on current iteration. */
            pmd_thread_ctx_time_update(pmd);
            tx_packets = dp_netdev_pmd_flush_output_packets(pmd, false);
        }

        //做些维护（每1024次进去一次）
        if (lc++ > 1024) {
            lc = 0;

            coverage_try_clear();
            dp_netdev_pmd_try_optimize(pmd, poll_list, poll_cnt);
            if (!ovsrcu_try_quiesce()) {
                emc_cache_slow_sweep(&((pmd->flow_cache).emc_cache));
            }

            for (i = 0; i < poll_cnt; i++) {
                uint64_t current_seq =
                         netdev_get_change_seq(poll_list[i].rxq->port->netdev);
                if (poll_list[i].change_seq != current_seq) {
                    poll_list[i].change_seq = current_seq;
                    poll_list[i].rxq_enabled =
                                 netdev_rxq_enabled(poll_list[i].rxq->rx);
                }
            }
        }

        atomic_read_explicit(&pmd->reload, &reload, memory_order_acquire);
        if (OVS_UNLIKELY(reload)) {
            break;
        }

        pmd_perf_end_iteration(s, rx_packets, tx_packets,
                               pmd_perf_metrics_enabled(pmd));
    }
    ovs_mutex_unlock(&pmd->perf_stats.stats_mutex);

    //重新加载收队列及发送port
    poll_cnt = pmd_load_queues_and_ports(pmd, &poll_list);
    atomic_read_relaxed(&pmd->wait_for_reload, &wait_for_reload);
    atomic_read_relaxed(&pmd->reload_tx_qid, &reload_tx_qid);
    atomic_read_relaxed(&pmd->exit, &exiting);
    /* Signal here to make sure the pmd finishes
     * reloading the updated configuration. */
    dp_netdev_pmd_reload_done(pmd);//知会reload操作已响应

    if (reload_tx_qid) {
        pmd_free_static_tx_qid(pmd);
        pmd_alloc_static_tx_qid(pmd);
    }

    if (!exiting) {
        goto reload;
    }

    pmd_free_static_tx_qid(pmd);
    dfc_cache_uninit(&pmd->flow_cache);
    free(poll_list);
    pmd_free_cached_ports(pmd);
    return NULL;
}

static void
dp_netdev_disable_upcall(struct dp_netdev *dp)
    OVS_ACQUIRES(dp->upcall_rwlock)
{
    fat_rwlock_wrlock(&dp->upcall_rwlock);
}


/* Meters */
static void
dpif_netdev_meter_get_features(const struct dpif * dpif OVS_UNUSED,
                               struct ofputil_meter_features *features)
{
    features->max_meters = MAX_METERS;
    features->band_types = DP_SUPPORTED_METER_BAND_TYPES;
    features->capabilities = DP_SUPPORTED_METER_FLAGS_MASK;
    features->max_bands = MAX_BANDS;
    features->max_color = 0;
}

/* Applies the meter identified by 'meter_id' to 'packets_'.  Packets
 * that exceed a band are dropped in-place. */
static void
dp_netdev_run_meter(struct dp_netdev *dp, struct dp_packet_batch *packets_,
                    uint32_t meter_id, long long int now)
{
    struct dp_meter *meter;
    struct dp_meter_band *band;
    struct dp_packet *packet;
    long long int long_delta_t; /* msec */
    uint32_t delta_t; /* msec */
    const size_t cnt = dp_packet_batch_size(packets_);
    uint32_t bytes, volume;
    int exceeded_band[NETDEV_MAX_BURST];
    uint32_t exceeded_rate[NETDEV_MAX_BURST];
    int exceeded_pkt = cnt; /* First packet that exceeded a band rate. */

    if (meter_id >= MAX_METERS) {
        return;
    }

    meter_lock(dp, meter_id);
    meter = dp->meters[meter_id];
    if (!meter) {
        goto out;
    }

    /* Initialize as negative values. */
    memset(exceeded_band, 0xff, cnt * sizeof *exceeded_band);
    /* Initialize as zeroes. */
    memset(exceeded_rate, 0, cnt * sizeof *exceeded_rate);

    /* All packets will hit the meter at the same time. */
    long_delta_t = now / 1000 - meter->used / 1000; /* msec */

    /* Make sure delta_t will not be too large, so that bucket will not
     * wrap around below. */
    delta_t = (long_delta_t > (long long int)meter->max_delta_t)
        ? meter->max_delta_t : (uint32_t)long_delta_t;

    /* Update meter stats. */
    meter->used = now;
    meter->packet_count += cnt;
    bytes = 0;
    DP_PACKET_BATCH_FOR_EACH (i, packet, packets_) {
        bytes += dp_packet_size(packet);
    }
    meter->byte_count += bytes;

    /* Meters can operate in terms of packets per second or kilobits per
     * second. */
    if (meter->flags & OFPMF13_PKTPS) {
        /* Rate in packets/second, bucket 1/1000 packets. */
        /* msec * packets/sec = 1/1000 packets. */
        volume = cnt * 1000; /* Take 'cnt' packets from the bucket. */
    } else {
        /* Rate in kbps, bucket in bits. */
        /* msec * kbps = bits */
        volume = bytes * 8;
    }

    /* Update all bands and find the one hit with the highest rate for each
     * packet (if any). */
    for (int m = 0; m < meter->n_bands; ++m) {
        band = &meter->bands[m];

        /* Update band's bucket. */
        band->bucket += delta_t * band->up.rate;
        if (band->bucket > band->up.burst_size) {
            band->bucket = band->up.burst_size;
        }

        /* Drain the bucket for all the packets, if possible. */
        if (band->bucket >= volume) {
            band->bucket -= volume;
        } else {
            int band_exceeded_pkt;

            /* Band limit hit, must process packet-by-packet. */
            if (meter->flags & OFPMF13_PKTPS) {
                band_exceeded_pkt = band->bucket / 1000;
                band->bucket %= 1000; /* Remainder stays in bucket. */

                /* Update the exceeding band for each exceeding packet.
                 * (Only one band will be fired by a packet, and that
                 * can be different for each packet.) */
                for (int i = band_exceeded_pkt; i < cnt; i++) {
                    if (band->up.rate > exceeded_rate[i]) {
                        exceeded_rate[i] = band->up.rate;
                        exceeded_band[i] = m;
                    }
                }
            } else {
                /* Packet sizes differ, must process one-by-one. */
                band_exceeded_pkt = cnt;
                DP_PACKET_BATCH_FOR_EACH (i, packet, packets_) {
                    uint32_t bits = dp_packet_size(packet) * 8;

                    if (band->bucket >= bits) {
                        band->bucket -= bits;
                    } else {
                        if (i < band_exceeded_pkt) {
                            band_exceeded_pkt = i;
                        }
                        /* Update the exceeding band for the exceeding packet.
                         * (Only one band will be fired by a packet, and that
                         * can be different for each packet.) */
                        if (band->up.rate > exceeded_rate[i]) {
                            exceeded_rate[i] = band->up.rate;
                            exceeded_band[i] = m;
                        }
                    }
                }
            }
            /* Remember the first exceeding packet. */
            if (exceeded_pkt > band_exceeded_pkt) {
                exceeded_pkt = band_exceeded_pkt;
            }
        }
    }

    /* Fire the highest rate band exceeded by each packet, and drop
     * packets if needed. */
    size_t j;
    DP_PACKET_BATCH_REFILL_FOR_EACH (j, cnt, packet, packets_) {
        if (exceeded_band[j] >= 0) {
            /* Meter drop packet. */
            band = &meter->bands[exceeded_band[j]];
            band->packet_count += 1;
            band->byte_count += dp_packet_size(packet);

            dp_packet_delete(packet);
        } else {
            /* Meter accepts packet. */
            dp_packet_batch_refill(packets_, packet, j);
        }
    }
 out:
    meter_unlock(dp, meter_id);
}

/* Meter set/get/del processing is still single-threaded. */
static int
dpif_netdev_meter_set(struct dpif *dpif, ofproto_meter_id meter_id,
                      struct ofputil_meter_config *config)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    uint32_t mid = meter_id.uint32;
    struct dp_meter *meter;
    int i;

    if (mid >= MAX_METERS) {
        return EFBIG; /* Meter_id out of range. */
    }

    if (config->flags & ~DP_SUPPORTED_METER_FLAGS_MASK) {
        return EBADF; /* Unsupported flags set */
    }

    if (config->n_bands > MAX_BANDS) {
        return EINVAL;
    }

    for (i = 0; i < config->n_bands; ++i) {
        switch (config->bands[i].type) {
        case OFPMBT13_DROP:
            break;
        default:
            return ENODEV; /* Unsupported band type */
        }
    }

    /* Allocate meter */
    meter = xzalloc(sizeof *meter
                    + config->n_bands * sizeof(struct dp_meter_band));

    meter->flags = config->flags;
    meter->n_bands = config->n_bands;
    meter->max_delta_t = 0;
    meter->used = time_usec();

    /* set up bands */
    for (i = 0; i < config->n_bands; ++i) {
        uint32_t band_max_delta_t;

        /* Set burst size to a workable value if none specified. */
        if (config->bands[i].burst_size == 0) {
            config->bands[i].burst_size = config->bands[i].rate;
        }

        meter->bands[i].up = config->bands[i];
        /* Convert burst size to the bucket units: */
        /* pkts => 1/1000 packets, kilobits => bits. */
        meter->bands[i].up.burst_size *= 1000;
        /* Initialize bucket to empty. */
        meter->bands[i].bucket = 0;

        /* Figure out max delta_t that is enough to fill any bucket. */
        band_max_delta_t
            = meter->bands[i].up.burst_size / meter->bands[i].up.rate;
        if (band_max_delta_t > meter->max_delta_t) {
            meter->max_delta_t = band_max_delta_t;
        }
    }

    meter_lock(dp, mid);
    dp_delete_meter(dp, mid); /* Free existing meter, if any */
    dp->meters[mid] = meter;
    meter_unlock(dp, mid);

    return 0;
}

static int
dpif_netdev_meter_get(const struct dpif *dpif,
                      ofproto_meter_id meter_id_,
                      struct ofputil_meter_stats *stats, uint16_t n_bands)
{
    const struct dp_netdev *dp = get_dp_netdev(dpif);
    uint32_t meter_id = meter_id_.uint32;
    int retval = 0;

    if (meter_id >= MAX_METERS) {
        return EFBIG;
    }

    meter_lock(dp, meter_id);
    const struct dp_meter *meter = dp->meters[meter_id];
    if (!meter) {
        retval = ENOENT;
        goto done;
    }
    if (stats) {
        int i = 0;

        stats->packet_in_count = meter->packet_count;
        stats->byte_in_count = meter->byte_count;

        for (i = 0; i < n_bands && i < meter->n_bands; ++i) {
            stats->bands[i].packet_count = meter->bands[i].packet_count;
            stats->bands[i].byte_count = meter->bands[i].byte_count;
        }

        stats->n_bands = i;
    }

done:
    meter_unlock(dp, meter_id);
    return retval;
}

static int
dpif_netdev_meter_del(struct dpif *dpif,
                      ofproto_meter_id meter_id_,
                      struct ofputil_meter_stats *stats, uint16_t n_bands)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    int error;

    error = dpif_netdev_meter_get(dpif, meter_id_, stats, n_bands);
    if (!error) {
        uint32_t meter_id = meter_id_.uint32;

        meter_lock(dp, meter_id);
        dp_delete_meter(dp, meter_id);
        meter_unlock(dp, meter_id);
    }
    return error;
}


static void
dpif_netdev_disable_upcall(struct dpif *dpif)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    dp_netdev_disable_upcall(dp);
}

static void
dp_netdev_enable_upcall(struct dp_netdev *dp)
    OVS_RELEASES(dp->upcall_rwlock)
{
    fat_rwlock_unlock(&dp->upcall_rwlock);
}

static void
dpif_netdev_enable_upcall(struct dpif *dpif)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    dp_netdev_enable_upcall(dp);
}

static void
dp_netdev_pmd_reload_done(struct dp_netdev_pmd_thread *pmd)
{
    atomic_store_relaxed(&pmd->wait_for_reload, false);
    atomic_store_relaxed(&pmd->reload_tx_qid, false);
    pmd->last_reload_seq = seq_read(pmd->reload_seq);
    atomic_store_explicit(&pmd->reload, false, memory_order_release);
}

/* Finds and refs the dp_netdev_pmd_thread on core 'core_id'.  Returns
 * the pointer if succeeds, otherwise, NULL (it can return NULL even if
 * 'core_id' is NON_PMD_CORE_ID).
 *
 * Caller must unrefs the returned reference.  */
//给定core_id查找其对应的pmd
static struct dp_netdev_pmd_thread *
dp_netdev_get_pmd(struct dp_netdev *dp, unsigned core_id)
{
    struct dp_netdev_pmd_thread *pmd;
    const struct cmap_node *pnode;

    pnode = cmap_find(&dp->poll_threads, hash_int(core_id, 0));
    if (!pnode) {
        return NULL;
    }
    pmd = CONTAINER_OF(pnode, struct dp_netdev_pmd_thread, node);

    return dp_netdev_pmd_try_ref(pmd) ? pmd : NULL;
}

/* Sets the 'struct dp_netdev_pmd_thread' for non-pmd threads. */
//生成non-pmd对应的pmd
static void
dp_netdev_set_nonpmd(struct dp_netdev *dp)
    OVS_REQUIRES(dp->port_mutex)
{
    struct dp_netdev_pmd_thread *non_pmd;

    non_pmd = xzalloc(sizeof *non_pmd);
    dp_netdev_configure_pmd(non_pmd, dp, NON_PMD_CORE_ID, OVS_NUMA_UNSPEC);
}

/* Caller must have valid pointer to 'pmd'. */
static bool
dp_netdev_pmd_try_ref(struct dp_netdev_pmd_thread *pmd)
{
    return ovs_refcount_try_ref_rcu(&pmd->ref_cnt);
}

static void
dp_netdev_pmd_unref(struct dp_netdev_pmd_thread *pmd)
{
    if (pmd && ovs_refcount_unref(&pmd->ref_cnt) == 1) {
        ovsrcu_postpone(dp_netdev_destroy_pmd, pmd);
    }
}

/* Given cmap position 'pos', tries to ref the next node.  If try_ref()
 * fails, keeps checking for next node until reaching the end of cmap.
 *
 * Caller must unrefs the returned reference. */
static struct dp_netdev_pmd_thread *
dp_netdev_pmd_get_next(struct dp_netdev *dp, struct cmap_position *pos)
{
    struct dp_netdev_pmd_thread *next;

    do {
        struct cmap_node *node;

        node = cmap_next_position(&dp->poll_threads, pos);
        next = node ? CONTAINER_OF(node, struct dp_netdev_pmd_thread, node)
            : NULL;
    } while (next && !dp_netdev_pmd_try_ref(next));

    return next;
}

/* Configures the 'pmd' based on the input argument. */
static void
dp_netdev_configure_pmd(struct dp_netdev_pmd_thread *pmd, struct dp_netdev *dp,
                        unsigned core_id, int numa_id)
{
    pmd->dp = dp;
    pmd->core_id = core_id;
    pmd->numa_id = numa_id;
    pmd->need_reload = false;
    pmd->n_output_batches = 0;

    ovs_refcount_init(&pmd->ref_cnt);
    atomic_init(&pmd->exit, false);
    pmd->reload_seq = seq_create();
    pmd->last_reload_seq = seq_read(pmd->reload_seq);
    atomic_init(&pmd->reload, false);
    ovs_mutex_init(&pmd->flow_mutex);
    ovs_mutex_init(&pmd->port_mutex);
    cmap_init(&pmd->flow_table);
    cmap_init(&pmd->classifiers);
    pmd->ctx.last_rxq = NULL;
    pmd_thread_ctx_time_update(pmd);
    pmd->next_optimization = pmd->ctx.now + DPCLS_OPTIMIZATION_INTERVAL;
    pmd->rxq_next_cycle_store = pmd->ctx.now + PMD_RXQ_INTERVAL_LEN;
    hmap_init(&pmd->poll_list);
    hmap_init(&pmd->tx_ports);
    hmap_init(&pmd->tnl_port_cache);
    hmap_init(&pmd->send_port_cache);
    /* init the 'flow_cache' since there is no
     * actual thread created for NON_PMD_CORE_ID. */
    if (core_id == NON_PMD_CORE_ID) {
        dfc_cache_init(&pmd->flow_cache);
        pmd_alloc_static_tx_qid(pmd);
    }
    pmd_perf_stats_init(&pmd->perf_stats);
    cmap_insert(&dp->poll_threads, CONST_CAST(struct cmap_node *, &pmd->node),
                hash_int(core_id, 0));//将pmd加入到dp中
}

static void
dp_netdev_destroy_pmd(struct dp_netdev_pmd_thread *pmd)
{
    struct dpcls *cls;

    dp_netdev_pmd_flow_flush(pmd);
    hmap_destroy(&pmd->send_port_cache);
    hmap_destroy(&pmd->tnl_port_cache);
    hmap_destroy(&pmd->tx_ports);
    hmap_destroy(&pmd->poll_list);
    /* All flows (including their dpcls_rules) have been deleted already */
    CMAP_FOR_EACH (cls, node, &pmd->classifiers) {
        dpcls_destroy(cls);
        ovsrcu_postpone(free, cls);
    }
    cmap_destroy(&pmd->classifiers);
    cmap_destroy(&pmd->flow_table);
    ovs_mutex_destroy(&pmd->flow_mutex);
    seq_destroy(pmd->reload_seq);
    ovs_mutex_destroy(&pmd->port_mutex);
    free(pmd);
}

/* Stops the pmd thread, removes it from the 'dp->poll_threads',
 * and unrefs the struct. */
//从dp上删除给定的pmd
static void
dp_netdev_del_pmd(struct dp_netdev *dp, struct dp_netdev_pmd_thread *pmd)
{
    /* NON_PMD_CORE_ID doesn't have a thread, so we don't have to synchronize,
     * but extra cleanup is necessary */
    if (pmd->core_id == NON_PMD_CORE_ID) {
        ovs_mutex_lock(&dp->non_pmd_mutex);
        dfc_cache_uninit(&pmd->flow_cache);
        pmd_free_cached_ports(pmd);
        pmd_free_static_tx_qid(pmd);
        ovs_mutex_unlock(&dp->non_pmd_mutex);
    } else {
        atomic_store_relaxed(&pmd->exit, true);//知会pmd需要退出
        dp_netdev_reload_pmd__(pmd);
        xpthread_join(pmd->thread, NULL);
    }

    dp_netdev_pmd_clear_ports(pmd);

    /* Purges the 'pmd''s flows after stopping the thread, but before
     * destroying the flows, so that the flow stats can be collected. */
    if (dp->dp_purge_cb) {
        dp->dp_purge_cb(dp->dp_purge_aux, pmd->core_id);
    }
    cmap_remove(&pmd->dp->poll_threads, &pmd->node, hash_int(pmd->core_id, 0));//将此pmd自poll_threads上移除
    dp_netdev_pmd_unref(pmd);
}

/* Destroys all pmd threads. If 'non_pmd' is true it also destroys the non pmd
 * thread. */
//删除dp上所有的pmd
static void
dp_netdev_destroy_all_pmds(struct dp_netdev *dp, bool non_pmd)
{
    struct dp_netdev_pmd_thread *pmd;
    struct dp_netdev_pmd_thread **pmd_list;
    size_t k = 0, n_pmds;

    n_pmds = cmap_count(&dp->poll_threads);
    pmd_list = xcalloc(n_pmds, sizeof *pmd_list);

    CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
        if (!non_pmd && pmd->core_id == NON_PMD_CORE_ID) {
            continue;
        }
        /* We cannot call dp_netdev_del_pmd(), since it alters
         * 'dp->poll_threads' (while we're iterating it) and it
         * might quiesce. */
        ovs_assert(k < n_pmds);
        pmd_list[k++] = pmd;
    }

    //删除dp上所有的pmd
    for (size_t i = 0; i < k; i++) {
        dp_netdev_del_pmd(dp, pmd_list[i]);
    }
    free(pmd_list);
}

/* Deletes all rx queues from pmd->poll_list and all the ports from
 * pmd->tx_ports. */
static void
dp_netdev_pmd_clear_ports(struct dp_netdev_pmd_thread *pmd)
{
    struct rxq_poll *poll;
    struct tx_port *port;

    ovs_mutex_lock(&pmd->port_mutex);
    HMAP_FOR_EACH_POP (poll, node, &pmd->poll_list) {
        free(poll);
    }
    HMAP_FOR_EACH_POP (port, node, &pmd->tx_ports) {
        free(port);
    }
    ovs_mutex_unlock(&pmd->port_mutex);
}

/* Adds rx queue to poll_list of PMD thread, if it's not there already. */
//向pmd中添加相应轮询队列
static void
dp_netdev_add_rxq_to_pmd(struct dp_netdev_pmd_thread *pmd,
                         struct dp_netdev_rxq *rxq)
    OVS_REQUIRES(pmd->port_mutex)
{
    int qid = netdev_rxq_get_queue_id(rxq->rx);
    uint32_t hash = hash_2words(odp_to_u32(rxq->port->port_no), qid);
    struct rxq_poll *poll;

    //检查收队列是否已加入到此pmd
    HMAP_FOR_EACH_WITH_HASH (poll, node, hash, &pmd->poll_list) {
        if (poll->rxq == rxq) {
            /* 'rxq' is already polled by this thread. Do nothing. */
            return;
        }
    }

    //构造poll,并加入到pmd->poll_list（以便pmd线程可以轮循环它）
    poll = xmalloc(sizeof *poll);
    poll->rxq = rxq;
    hmap_insert(&pmd->poll_list, &poll->node, hash);

    //知会reconfigure_datapath需要reload（然后其会通知pmd线程）
    pmd->need_reload = true;
}

/* Delete 'poll' from poll_list of PMD thread. */
//将指定队列自pmd中移除，使其不再poll
static void
dp_netdev_del_rxq_from_pmd(struct dp_netdev_pmd_thread *pmd,
                           struct rxq_poll *poll)
    OVS_REQUIRES(pmd->port_mutex)
{
    hmap_remove(&pmd->poll_list, &poll->node);
    free(poll);

    pmd->need_reload = true;//知会pmd重新load
}

/* Add 'port' to the tx port cache of 'pmd', which must be reloaded for the
 * changes to take effect. */
//将此port加入到pmd的转发port
static void
dp_netdev_add_port_tx_to_pmd(struct dp_netdev_pmd_thread *pmd,
                             struct dp_netdev_port *port)//将此port加入到pmd的转发port
    OVS_REQUIRES(pmd->port_mutex)
{
    struct tx_port *tx;

    tx = tx_port_lookup(&pmd->tx_ports, port->port_no);
    if (tx) {
        /* 'port' is already on this thread tx cache. Do nothing. */
        return;//已存在，不再加入
    }

    tx = xzalloc(sizeof *tx);

    tx->port = port;
    tx->qid = -1;
    tx->flush_time = 0LL;
    dp_packet_batch_init(&tx->output_pkts);

    hmap_insert(&pmd->tx_ports, &tx->node, hash_port_no(tx->port->port_no));
    pmd->need_reload = true;
}

/* Del 'tx' from the tx port cache of 'pmd', which must be reloaded for the
 * changes to take effect. */
static void
dp_netdev_del_port_tx_from_pmd(struct dp_netdev_pmd_thread *pmd,
                               struct tx_port *tx)
    OVS_REQUIRES(pmd->port_mutex)
{
    hmap_remove(&pmd->tx_ports, &tx->node);
    free(tx);
    pmd->need_reload = true;
}

static char *
dpif_netdev_get_datapath_version(void)
{
     return xstrdup("<built-in>");
}

//更新流的统计信息
static void
dp_netdev_flow_used(struct dp_netdev_flow *netdev_flow, int cnt, int size,
                    uint16_t tcp_flags, long long now)
{
    uint16_t flags;

    atomic_store_relaxed(&netdev_flow->stats.used, now);
    non_atomic_ullong_add(&netdev_flow->stats.packet_count, cnt);
    non_atomic_ullong_add(&netdev_flow->stats.byte_count, size);
    atomic_read_relaxed(&netdev_flow->stats.tcp_flags, &flags);
    flags |= tcp_flags;
    atomic_store_relaxed(&netdev_flow->stats.tcp_flags, flags);
}

static int
dp_netdev_upcall(struct dp_netdev_pmd_thread *pmd, struct dp_packet *packet_,
                 struct flow *flow, struct flow_wildcards *wc, ovs_u128 *ufid,
                 enum dpif_upcall_type type, const struct nlattr *userdata,
                 struct ofpbuf *actions, struct ofpbuf *put_actions)
{
    struct dp_netdev *dp = pmd->dp;

    if (OVS_UNLIKELY(!dp->upcall_cb)) {
    	//此datapath设备无upcall_cb，则返回
        return ENODEV;
    }

    //debug代码
    if (OVS_UNLIKELY(!VLOG_DROP_DBG(&upcall_rl))) {
        struct ds ds = DS_EMPTY_INITIALIZER;
        char *packet_str;
        struct ofpbuf key;
        struct odp_flow_key_parms odp_parms = {
            .flow = flow,
            .mask = wc ? &wc->masks : NULL,
            .support = dp_netdev_support,
        };

        ofpbuf_init(&key, 0);
        odp_flow_key_from_flow(&odp_parms, &key);
        packet_str = ofp_dp_packet_to_string(packet_);

        odp_flow_key_format(key.data, key.size, &ds);

        VLOG_DBG("%s: %s upcall:\n%s\n%s", dp->name,
                 dpif_upcall_type_to_string(type), ds_cstr(&ds), packet_str);

        ofpbuf_uninit(&key);
        free(packet_str);

        ds_destroy(&ds);
    }

    //upcall_cb回调调用
    return dp->upcall_cb(packet_, flow, ufid, pmd->core_id, type, userdata,
                         actions, wc, put_actions, dp->upcall_aux);
}

//取rss hash
static inline uint32_t
dpif_netdev_packet_get_rss_hash_orig_pkt(struct dp_packet *packet,
                                const struct miniflow *mf)
{
    uint32_t hash;

    if (OVS_LIKELY(dp_packet_rss_valid(packet))) {
        hash = dp_packet_get_rss_hash(packet);
    } else {
        hash = miniflow_hash_5tuple(mf, 0);
        dp_packet_set_rss_hash(packet, hash);
    }

    return hash;
}

static inline uint32_t
dpif_netdev_packet_get_rss_hash(struct dp_packet *packet,
                                const struct miniflow *mf)
{
    uint32_t hash, recirc_depth;

    if (OVS_LIKELY(dp_packet_rss_valid(packet))) {
        hash = dp_packet_get_rss_hash(packet);
    } else {
        hash = miniflow_hash_5tuple(mf, 0);
        dp_packet_set_rss_hash(packet, hash);
    }

    /* The RSS hash must account for the recirculation depth to avoid
     * collisions in the exact match cache */
    recirc_depth = *recirc_depth_get_unsafe();
    if (OVS_UNLIKELY(recirc_depth)) {
        hash = hash_finish(hash, recirc_depth);
        dp_packet_set_rss_hash(packet, hash);
    }
    return hash;
}

//命中同一条流的batch
struct packet_batch_per_flow {
    unsigned int byte_count;//同批次字节数
    uint16_t tcp_flags;//同批次tcp flags
    struct dp_netdev_flow *flow;//同批次命中的flow

    struct dp_packet_batch array;//同批次的报文组
};

static inline void
packet_batch_per_flow_update(struct packet_batch_per_flow *batch,
                             struct dp_packet *packet,
                             uint16_t tcp_flags)
{
    batch->byte_count += dp_packet_size(packet);
    batch->tcp_flags |= tcp_flags;
    //将此packet，归类到对应的batch中
    dp_packet_batch_add(&batch->array, packet);
}

static inline void
packet_batch_per_flow_init(struct packet_batch_per_flow *batch,
                           struct dp_netdev_flow *flow)
{
    flow->batch = batch;

    batch->flow = flow;
    dp_packet_batch_init(&batch->array);
    batch->byte_count = 0;
    batch->tcp_flags = 0;
}

//按流执行action
static inline void
packet_batch_per_flow_execute(struct packet_batch_per_flow *batch,
                              struct dp_netdev_pmd_thread *pmd)
{
    struct dp_netdev_actions *actions;
    struct dp_netdev_flow *flow = batch->flow;//此批次对应的flow

    dp_netdev_flow_used(flow, dp_packet_batch_size(&batch->array),
                        batch->byte_count,
                        batch->tcp_flags, pmd->ctx.now / 1000);

    //取flow对应的action
    actions = dp_netdev_flow_get_actions(flow);

    //采用actions执行这一批次的报文batch->array
    dp_netdev_execute_actions(pmd, &batch->array, true, &flow->flow,
                              actions->actions, actions->size);
}

//将packet加入到按flow划分的batches中，n_batches表示如果此flow没有对应的batch,则可使用空结构的索引号
static inline void
dp_netdev_queue_batches(struct dp_packet *pkt,
                        struct dp_netdev_flow *flow, uint16_t tcp_flags,
                        struct packet_batch_per_flow *batches,
                        size_t *n_batches)
{
    struct packet_batch_per_flow *batch = flow->batch;

    if (OVS_UNLIKELY(!batch)) {
        batch = &batches[(*n_batches)++];//n_batches记录了之前有多个batches已分配，我们这里取一个空的
        packet_batch_per_flow_init(batch, flow);//设置packet的batch,flow
    }

    packet_batch_per_flow_update(batch, pkt, tcp_flags);//更新batch信息
}

//将packet存入flow_map中
static inline void
packet_enqueue_to_flow_map(struct dp_packet *packet,
                           struct dp_netdev_flow *flow,
                           uint16_t tcp_flags,
                           struct dp_packet_flow_map *flow_map,
                           size_t index)
{
    struct dp_packet_flow_map *map = &flow_map[index];
    map->flow = flow;
    map->packet = packet;
    map->tcp_flags = tcp_flags;
}

/* SMC lookup function for a batch of packets.
 * By doing batching SMC lookup, we can use prefetch
 * to hide memory access latency.
 */
static inline void
smc_lookup_batch(struct dp_netdev_pmd_thread *pmd,
            struct netdev_flow_key *keys,
            struct netdev_flow_key **missed_keys,
            struct dp_packet_batch *packets_,
            const int cnt,
            struct dp_packet_flow_map *flow_map,
            uint8_t *index_map)
{
    int i;
    struct dp_packet *packet;
    size_t n_smc_hit = 0, n_missed = 0;
    struct dfc_cache *cache = &pmd->flow_cache;
    struct smc_cache *smc_cache = &cache->smc_cache;
    const struct cmap_node *flow_node;
    int recv_idx;
    uint16_t tcp_flags;

    /* Prefetch buckets for all packets */
    for (i = 0; i < cnt; i++) {
        OVS_PREFETCH(&smc_cache->buckets[keys[i].hash & SMC_MASK]);
    }

    //遍历packets_中的所有报文
    DP_PACKET_BATCH_REFILL_FOR_EACH (i, cnt, packet, packets_) {
        struct dp_netdev_flow *flow = NULL;
        flow_node = smc_entry_get(pmd, keys[i].hash);
        bool hit = false;
        /* Get the original order of this packet in received batch. */
        recv_idx = index_map[i];

        if (OVS_LIKELY(flow_node != NULL)) {
            CMAP_NODE_FOR_EACH (flow, node, flow_node) {
                /* Since we dont have per-port megaflow to check the port
                 * number, we need to  verify that the input ports match. */
                if (OVS_LIKELY(dpcls_rule_matches_key(&flow->cr, &keys[i]) &&
                flow->flow.in_port.odp_port == packet->md.in_port.odp_port)) {
                    tcp_flags = miniflow_get_tcp_flags(&keys[i].mf);

                    /* SMC hit and emc miss, we insert into EMC */
                    keys[i].len =
                        netdev_flow_key_size(miniflow_n_values(&keys[i].mf));
                    emc_probabilistic_insert(pmd, &keys[i], flow);
                    /* Add these packets into the flow map in the same order
                     * as received.
                     */
                    packet_enqueue_to_flow_map(packet, flow, tcp_flags,
                                               flow_map, recv_idx);
                    n_smc_hit++;
                    hit = true;
                    break;
                }
            }
            if (hit) {
                continue;
            }
        }

        /* SMC missed. Group missed packets together at
         * the beginning of the 'packets' array. */
        dp_packet_batch_refill(packets_, packet, i);

        /* Preserve the order of packet for flow batching. */
        index_map[n_missed] = recv_idx;

        /* Put missed keys to the pointer arrays return to the caller */
        missed_keys[n_missed++] = &keys[i];
    }

    pmd_perf_update_counter(&pmd->perf_stats, PMD_STAT_SMC_HIT, n_smc_hit);
}

/* Try to process all ('cnt') the 'packets' using only the datapath flow cache
 * 'pmd->flow_cache'. If a flow is not found for a packet 'packets[i]', the
 * miniflow is copied into 'keys' and the packet pointer is moved at the
 * beginning of the 'packets' array. The pointers of missed keys are put in the
 * missed_keys pointer array for future processing.
 *
 * The function returns the number of packets that needs to be processed in the
 * 'packets' array (they have been moved to the beginning of the vector).
 *
 * For performance reasons a caller may choose not to initialize the metadata
 * in 'packets_'.  If 'md_is_valid' is false, the metadata in 'packets'
 * is not valid and must be initialized by this function using 'port_no'.
 * If 'md_is_valid' is true, the metadata is already valid and 'port_no'
 * will be ignored.
 */
static inline size_t
dfc_processing(struct dp_netdev_pmd_thread *pmd,
               struct dp_packet_batch *packets_/*待处理的报文*/,
               struct netdev_flow_key *keys/*出参，每个报文对应的key*/,
               struct netdev_flow_key **missed_keys/*出参，没有在emc cache中查找到flow的keys*/,
               struct packet_batch_per_flow batches[], size_t *n_batches,/*出参，有多少个per_flow batches*/
               struct dp_packet_flow_map *flow_map/*出参，指明报文与flow间的对应关系*/,
               size_t *n_flows/*出参，flow_map的使用量*/, uint8_t *index_map,
               bool md_is_valid, odp_port_t port_no)
{
    struct netdev_flow_key *key = &keys[0];

    //n_missed为失配的packets数目，n_emc_hit为命中的packets数目
    size_t n_missed = 0, n_emc_hit = 0;
    struct dfc_cache *cache = &pmd->flow_cache;
    struct dp_packet *packet;

    //待处理的报文数目
    const size_t cnt = dp_packet_batch_size(packets_);
    uint32_t cur_min = pmd->ctx.emc_insert_min;
    int i;
    uint16_t tcp_flags;
    bool smc_enable_db;
    size_t map_cnt = 0;
    bool batch_enable = true;

    atomic_read_relaxed(&pmd->dp->smc_enable_db, &smc_enable_db);
    pmd_perf_update_counter(&pmd->perf_stats,
                            md_is_valid ? PMD_STAT_RECIRC : PMD_STAT_RECV,
                            cnt);

    //采用packet逐个遍历packets_中的所有报文，cnt为报文总体，i为当前packet对应的索引
    DP_PACKET_BATCH_REFILL_FOR_EACH (i/*指出报文编号*/, cnt, packet, packets_) {
        struct dp_netdev_flow *flow;
        uint32_t mark;

        //比标准以太头还要小，丢
        if (OVS_UNLIKELY(dp_packet_size(packet) < ETH_HEADER_LEN)) {
            dp_packet_delete(packet);//buf释放
            continue;
        }

        if (i != cnt - 1) {
        	//如果不是最后一个，则预取下一个包
            struct dp_packet **packets = packets_->packets;
            /* Prefetch next packet data and metadata. */
            OVS_PREFETCH(dp_packet_data(packets[i+1]));//预取下一个报文的数据（64字节）
            pkt_metadata_prefetch_init(&packets[i+1]->md);//预取metadata中的部分数据
        }

        if (!md_is_valid) {
        	//如果元数据还未初始化，初始化它(主要是设置入接口）
            pkt_metadata_init(&packet->md, port_no);
        }

        if ((*recirc_depth_get() == 0) &&
            dp_packet_has_flow_mark(packet, &mark)) {
            flow = mark_to_flow_find(pmd, mark);
            if (OVS_LIKELY(flow)) {
                tcp_flags = parse_tcp_flags(packet);
                if (OVS_LIKELY(batch_enable)) {
                	//将packet存入此flow上的batch中
                    dp_netdev_queue_batches(packet, flow, tcp_flags, batches,
                                            n_batches);
                } else {
                    /* Flow batching should be performed only after fast-path
                     * processing is also completed for packets with emc miss
                     * or else it will result in reordering of packets with
                     * same datapath flows. */
                    packet_enqueue_to_flow_map(packet, flow, tcp_flags,
                                               flow_map, map_cnt++);
                }
                continue;
            }
        }

        //解析此packet,将解析到的内容填充在key的minflow中
        miniflow_extract(packet, &key->mf);
	//实际上我们已经填充了buf，但这里不为len赋值
        key->len = 0; /* Not computed yet. */
        key->hash =
                (md_is_valid == false)
                ? dpif_netdev_packet_get_rss_hash_orig_pkt(packet, &key->mf)
                : dpif_netdev_packet_get_rss_hash(packet, &key->mf);

        /* If EMC is disabled skip emc_lookup */
        //执行emc cache查询
        flow = (cur_min != 0) ? emc_lookup(&cache->emc_cache, key) : NULL;
        if (OVS_LIKELY(flow)) {
        	//此报文命中的emc cache
            tcp_flags = miniflow_get_tcp_flags(&key->mf);
            n_emc_hit++;
            if (OVS_LIKELY(batch_enable)) {
                //如果emc命中，则尝试将packet_batch 归类到flow_batch中
                dp_netdev_queue_batches(packet, flow, tcp_flags, batches,
                                        n_batches);
            } else {
                /* Flow batching should be performed only after fast-path
                 * processing is also completed for packets with emc miss
                 * or else it will result in reordering of packets with
                 * same datapath flows. */
            	//指明flow与packet的映射关系，将此关系存入到flow_map中
                packet_enqueue_to_flow_map(packet, flow, tcp_flags,
                                           flow_map, map_cnt++);
            }
        } else {
            /* Exact match cache missed. Group missed packets together at
             * the beginning of the 'packets' array. */
        	//DP_PACKET_BATCH_REFILL_FOR_EACH 中我们将packets_->count已清为0，将packet放入packets_->count位置
        	//这个报文没有命中emc,这里将其重新放回到packets_(需要按顺序放回）
            dp_packet_batch_refill(packets_, packet, i);

            /* Preserve the order of packet for flow batching. */
            //指明此packets没有命中flow
            index_map[n_missed] = map_cnt;
            flow_map[map_cnt++].flow = NULL;

            /* 'key[n_missed]' contains the key of the current packet and it
             * will be passed to SMC lookup. The next key should be extracted
             * to 'keys[n_missed + 1]'.
             * We also maintain a pointer array to keys missed both SMC and EMC
             * which will be returned to the caller for future processing. */
            missed_keys[n_missed] = key;
            //分配下一次解析用的key(由于有n_missed个报文，故keys缓冲区被用了n_missed个)
            key = &keys[++n_missed];//已填充这个missing报文对应的packet，取下一个未用的

            /* Skip batching for subsequent packets to avoid reordering. */
            batch_enable = false;
        }
    }
    /* Count of packets which are not flow batched. */
    *n_flows = map_cnt;

    pmd_perf_update_counter(&pmd->perf_stats, PMD_STAT_EXACT_HIT, n_emc_hit);

    if (!smc_enable_db) {
        return dp_packet_batch_size(packets_);
    }

    //记录exact匹配命中数
    /* Packets miss EMC will do a batch lookup in SMC if enabled */
    smc_lookup_batch(pmd, keys, missed_keys, packets_,
                     n_missed, flow_map, index_map);
    return dp_packet_batch_size(packets_);//返回有多少个报文没有命中
}

static inline int
handle_packet_upcall(struct dp_netdev_pmd_thread *pmd,
                     struct dp_packet *packet,
                     const struct netdev_flow_key *key,
                     struct ofpbuf *actions, struct ofpbuf *put_actions)
{
    struct ofpbuf *add_actions;
    struct dp_packet_batch b;
    struct match match;
    ovs_u128 ufid;
    int error;
    uint64_t cycles = cycles_counter_update(&pmd->perf_stats);

    match.tun_md.valid = false;
    //在进行l1,l2查询时，我们没有使用展开的flow,这里我们使用展开的flow,将minflow㞡开到flow中
    miniflow_expand(&key->mf, &match.flow);
    memset(&match.wc, 0, sizeof match.wc);

    ofpbuf_clear(actions);
    ofpbuf_clear(put_actions);

    dpif_flow_hash(pmd->dp->dpif, &match.flow, sizeof match.flow, &ufid);//生成流对应的hash(ufid)

    //走upcall处理(actions,put_actions将被返回，如果put_actions->size为０，则action才会被加入）
    //设置类型为流表缺失流程
    error = dp_netdev_upcall(pmd, packet, &match.flow, &match.wc,
                             &ufid, DPIF_UC_MISS, NULL, actions,
                             put_actions);
    if (OVS_UNLIKELY(error && error != ENOSPC)) {//有error,但error不为ENOSPC,则丢包
        dp_packet_delete(packet);
        return error;
    }

    /* The Netlink encoding of datapath flow keys cannot express
     * wildcarding the presence of a VLAN tag. Instead, a missing VLAN
     * tag is interpreted as exact match on the fact that there is no
     * VLAN.  Unless we refactor a lot of code that translates between
     * Netlink and struct flow representations, we have to do the same
     * here.  This must be in sync with 'match' in dpif_netdev_flow_put(). */
    if (!match.wc.masks.vlans[0].tci) {
        match.wc.masks.vlans[0].tci = htons(0xffff);
    }

    /* We can't allow the packet batching in the next loop to execute
     * the actions.  Otherwise, if there are any slow path actions,
     * we'll send the packet up twice. */
    dp_packet_batch_init_packet(&b, packet);
    dp_netdev_execute_actions(pmd, &b, true, &match.flow,
                              actions->data, actions->size);//执行动作（执行的是actions中的动作）

    //如果put_actions存在，则加put_actions,否则使用actions
    add_actions = put_actions->size ? put_actions : actions;
    if (OVS_LIKELY(error != ENOSPC)) {
    	//说明成功执行了（前面对有错误，但错误不是ENOSPC的已处理）
        struct dp_netdev_flow *netdev_flow;

        /* XXX: There's a race window where a flow covering this packet
         * could have already been installed since we last did the flow
         * lookup before upcall.  This could be solved by moving the
         * mutex lock outside the loop, but that's an awful long time
         * to be locking revalidators out of making flow modifications. */
        ovs_mutex_lock(&pmd->flow_mutex);
        netdev_flow = dp_netdev_pmd_lookup_flow(pmd, key, NULL);
        if (OVS_LIKELY(!netdev_flow)) {
        	//当前还没有人加入此条规则，我们来加入它
            netdev_flow = dp_netdev_flow_add(pmd, &match, &ufid,
                                             add_actions->data,
                                             add_actions->size);//l2层cache维护入口(将此flow加入）
        }
        ovs_mutex_unlock(&pmd->flow_mutex);
        uint32_t hash = dp_netdev_flow_hash(&netdev_flow->ufid);
        smc_insert(pmd, key, hash);
        //向flow缓存中加入
        emc_probabilistic_insert(pmd, key, netdev_flow);
    }
    if (pmd_perf_metrics_enabled(pmd)) {
        /* Update upcall stats. */
        cycles = cycles_counter_update(&pmd->perf_stats) - cycles;
        struct pmd_perf_stats *s = &pmd->perf_stats;
        s->current.upcalls++;
        s->current.upcall_cycles += cycles;
        histogram_add_sample(&s->cycles_per_upcall, cycles);
    }
    return error;
}

//执行l2,l3查询
static inline void
fast_path_processing(struct dp_netdev_pmd_thread *pmd,
                     struct dp_packet_batch *packets_,
                     struct netdev_flow_key **keys/*入参，待处理报文的key*/,
                     struct dp_packet_flow_map *flow_map,
                     uint8_t *index_map,
                     odp_port_t in_port)
{
    const size_t cnt = dp_packet_batch_size(packets_);
#if !defined(__CHECKER__) && !defined(_WIN32)
    const size_t PKT_ARRAY_SIZE = cnt;
#else
    /* Sparse or MSVC doesn't like variable length array. */
    enum { PKT_ARRAY_SIZE = NETDEV_MAX_BURST };
#endif
    struct dp_packet *packet;
    struct dpcls *cls;
    struct dpcls_rule *rules[PKT_ARRAY_SIZE];
    struct dp_netdev *dp = pmd->dp;
    int upcall_ok_cnt = 0, upcall_fail_cnt = 0;
    int lookup_cnt = 0, add_lookup_cnt;
    bool any_miss;

    for (size_t i = 0; i < cnt; i++) {
        /* Key length is needed in all the cases, hash computed on demand. */
    	//设置在emc中解释后key解释出来的数据长度
        keys[i]->len = netdev_flow_key_size(miniflow_n_values(&keys[i]->mf));
    }

    /* Get the classifier for the in_port */
    //获得通过in_port的分类
    cls = dp_netdev_pmd_lookup_dpcls(pmd, in_port);
    if (OVS_LIKELY(cls)) {
        any_miss = !dpcls_lookup(cls, (const struct netdev_flow_key **)keys,
                                rules, cnt, &lookup_cnt);
    } else {
        any_miss = true;
        memset(rules, 0, sizeof(rules));
    }

    //没有在cls中查询到，准备upcall(拿到upcall的锁，则成功进入，默认都可拿到）
    if (OVS_UNLIKELY(any_miss) && !fat_rwlock_tryrdlock(&dp->upcall_rwlock)) {
        uint64_t actions_stub[512 / 8], slow_stub[512 / 8];
        struct ofpbuf actions, put_actions;

        //用actions_stub,slow_stub初始化actions,put_actions
        ofpbuf_use_stub(&actions, actions_stub, sizeof actions_stub);
        ofpbuf_use_stub(&put_actions, slow_stub, sizeof slow_stub);

        DP_PACKET_BATCH_FOR_EACH (i, packet, packets_) {
            struct dp_netdev_flow *netdev_flow;

            if (OVS_LIKELY(rules[i])) {
                continue;
            }

            /* It's possible that an earlier slow path execution installed
             * a rule covering this flow.  In this case, it's a lot cheaper
             * to catch it here than execute a miss. */
            //由于这里在一个循环里进行批量处理，我们认为handle_packet_upcall是比较慢的
            //所以后面的报文有可能因为handle_packet_upcall的调用中加入了新的flow而导致
            //月能查到了，所以这里针对没有查到的flow,再执行一次l2查询，如果找到就continue
            //否则走handle_packet_upcall　（已经要查l3了，所以就不妨在慢一点，期待捡个现成的。:-P)
            netdev_flow = dp_netdev_pmd_lookup_flow(pmd, keys[i],
                                                    &add_lookup_cnt);
            if (netdev_flow) {
                lookup_cnt += add_lookup_cnt;
                rules[i] = &netdev_flow->cr;
                continue;
            }

            //向上走upcall查询
            int error = handle_packet_upcall(pmd, packet, keys[i],
                                             &actions, &put_actions);

            if (OVS_UNLIKELY(error)) {
                upcall_fail_cnt++;
            } else {
                upcall_ok_cnt++;
            }
        }

        ofpbuf_uninit(&actions);
        ofpbuf_uninit(&put_actions);
        fat_rwlock_unlock(&dp->upcall_rwlock);
    } else if (OVS_UNLIKELY(any_miss)) {
        //否则丢包
        DP_PACKET_BATCH_FOR_EACH (i, packet, packets_) {
            if (OVS_UNLIKELY(!rules[i])) {
                dp_packet_delete(packet);
                upcall_fail_cnt++;
            }
        }
    }

    DP_PACKET_BATCH_FOR_EACH (i, packet, packets_) {
        struct dp_netdev_flow *flow;
        /* Get the original order of this packet in received batch. */
        int recv_idx = index_map[i];
        uint16_t tcp_flags;

        if (OVS_UNLIKELY(!rules[i])) {
            continue;
        }

        flow = dp_netdev_flow_cast(rules[i]);
        uint32_t hash =  dp_netdev_flow_hash(&flow->ufid);
        smc_insert(pmd, keys[i], hash);

        //2层缓冲，对１层缓存的维护入口（将我们刚找到的这些加入到flow_cache中）
        emc_probabilistic_insert(pmd, keys[i], flow);
        /* Add these packets into the flow map in the same order
         * as received.
         */
	//将报文按flow划入不同batch中
        tcp_flags = miniflow_get_tcp_flags(&keys[i]->mf);
        packet_enqueue_to_flow_map(packet, flow, tcp_flags,
                                   flow_map, recv_idx);
    }

    pmd_perf_update_counter(&pmd->perf_stats, PMD_STAT_MASKED_HIT,
                            cnt - upcall_ok_cnt - upcall_fail_cnt);
    pmd_perf_update_counter(&pmd->perf_stats, PMD_STAT_MASKED_LOOKUP,
                            lookup_cnt);
    pmd_perf_update_counter(&pmd->perf_stats, PMD_STAT_MISS,
                            upcall_ok_cnt);
    pmd_perf_update_counter(&pmd->perf_stats, PMD_STAT_LOST,
                            upcall_fail_cnt);
}

/* Packets enter the datapath from a port (or from recirculation) here.
 *
 * When 'md_is_valid' is true the metadata in 'packets' are already valid.
 * When false the metadata in 'packets' need to be initialized. */
static void
dp_netdev_input__(struct dp_netdev_pmd_thread *pmd,
                  struct dp_packet_batch *packets,
                  bool md_is_valid, odp_port_t port_no)//port_no表示报文自哪个接口来
{
#if !defined(__CHECKER__) && !defined(_WIN32)
    const size_t PKT_ARRAY_SIZE = dp_packet_batch_size(packets);
#else
    /* Sparse or MSVC doesn't like variable length array. */
    enum { PKT_ARRAY_SIZE = NETDEV_MAX_BURST };
#endif
    OVS_ALIGNED_VAR(CACHE_LINE_SIZE)
    struct netdev_flow_key keys[PKT_ARRAY_SIZE];
    struct netdev_flow_key *missed_keys[PKT_ARRAY_SIZE];

    //最坏的情况下，cnt个包，会被放在cnt个batches中（这里利用batches合并命中同一个flow的batch)
    //报文在emc处理时将填充在batches中
    struct packet_batch_per_flow batches[PKT_ARRAY_SIZE];
    size_t n_batches;
    struct dp_packet_flow_map flow_map[PKT_ARRAY_SIZE];
    uint8_t index_map[PKT_ARRAY_SIZE];
    size_t n_flows, i;

    odp_port_t in_port;

    //填充到多少个了
    n_batches = 0;

    //执行报文解析，并查询emc cache
    dfc_processing(pmd, packets, keys, missed_keys, batches, &n_batches,
                   flow_map, &n_flows, index_map, md_is_valid, port_no);

    if (!dp_packet_batch_is_empty(packets)) {
        //检查发现emc没有完全命中完
        /* Get ingress port from first packet's metadata. */
        in_port = packets->packets[0]->md.in_port.odp_port;
	    //执行l2,l3查询
        fast_path_processing(pmd, packets, missed_keys,
                             flow_map, index_map, in_port);
    }

    /* Batch rest of packets which are in flow map. */
    for (i = 0; i < n_flows; i++) {
        struct dp_packet_flow_map *map = &flow_map[i];

        if (OVS_UNLIKELY(!map->flow)) {
        	//跳过未命中flow的packet
            continue;
        }
        dp_netdev_queue_batches(map->packet, map->flow, map->tcp_flags,
                                batches, &n_batches);
     }

    /* All the flow batches need to be reset before any call to
     * packet_batch_per_flow_execute() as it could potentially trigger
     * recirculation. When a packet matching flow ‘j’ happens to be
     * recirculated, the nested call to dp_netdev_input__() could potentially
     * classify the packet as matching another flow - say 'k'. It could happen
     * that in the previous call to dp_netdev_input__() that same flow 'k' had
     * already its own batches[k] still waiting to be served.  So if its
     * ‘batch’ member is not reset, the recirculated packet would be wrongly
     * appended to batches[k] of the 1st call to dp_netdev_input__(). */
    for (i = 0; i < n_batches; i++) {
    	//在按flow归类报文时为了方便临时用了这个值，为不影响下次结果，将其还原为NULL
        batches[i].flow->batch = NULL;
    }

    //现在一共有n_batches条流被命中，按流执行
    for (i = 0; i < n_batches; i++) {
        packet_batch_per_flow_execute(&batches[i], pmd);//统一进行动作处理
    }
}


static void
dp_netdev_input(struct dp_netdev_pmd_thread *pmd,
                struct dp_packet_batch *packets,
                odp_port_t port_no)
{
	//对刚收上来的报进行处理，此时原数据是无效的，传false
	dp_netdev_input__(pmd, packets, false, port_no);
}

//处理过程中，报文需要回炉重查，此时元数据是有效的，传true
static void
dp_netdev_recirculate(struct dp_netdev_pmd_thread *pmd,
                      struct dp_packet_batch *packets)
{
    dp_netdev_input__(pmd, packets, true, 0);//入接口未知
}

struct dp_netdev_execute_aux {
    struct dp_netdev_pmd_thread *pmd;
    const struct flow *flow;
};

static void
dpif_netdev_register_dp_purge_cb(struct dpif *dpif, dp_purge_callback *cb,
                                 void *aux)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    dp->dp_purge_aux = aux;
    dp->dp_purge_cb = cb;
}

static void
dpif_netdev_register_upcall_cb(struct dpif *dpif, upcall_callback *cb,
                               void *aux)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    dp->upcall_aux = aux;
    dp->upcall_cb = cb;
}

static void
dpif_netdev_xps_revalidate_pmd(const struct dp_netdev_pmd_thread *pmd,
                               bool purge)
{
    struct tx_port *tx;
    struct dp_netdev_port *port;
    long long interval;

    HMAP_FOR_EACH (tx, node, &pmd->send_port_cache) {
        if (!tx->port->dynamic_txqs) {
            continue;
        }
        //支持XPS的所有txport，如果间隔过大，或者要拔出，则无效qid
        interval = pmd->ctx.now - tx->last_used;
        if (tx->qid >= 0 && (purge || interval >= XPS_TIMEOUT)) {
            port = tx->port;
            ovs_mutex_lock(&port->txq_used_mutex);
            port->txq_used[tx->qid]--;
            ovs_mutex_unlock(&port->txq_used_mutex);
            tx->qid = -1;
        }
    }
}

static int
dpif_netdev_xps_get_tx_qid(const struct dp_netdev_pmd_thread *pmd,
                           struct tx_port *tx)
{
    struct dp_netdev_port *port;
    long long interval;
    int i, min_cnt, min_qid;

    interval = pmd->ctx.now - tx->last_used;
    tx->last_used = pmd->ctx.now;

    //选定后，间隔在XPS_TIMEOUT_MS时间内有效
    if (OVS_LIKELY(tx->qid >= 0 && interval < XPS_TIMEOUT)) {
        return tx->qid;
    }

    port = tx->port;

    ovs_mutex_lock(&port->txq_used_mutex);
    if (tx->qid >= 0) {
        //减少tx->qid队列的使用计数，无效上次选定的qid
    		port->txq_used[tx->qid]--;
        tx->qid = -1;
    }

    min_cnt = -1;
    min_qid = 0;
    //遍历当前netdev的所有tx队列，如果其使用计数，最小，则记录其队列id
    //选择出port中使用计数最小的tx队列
    for (i = 0; i < netdev_n_txq(port->netdev); i++) {
        if (port->txq_used[i] < min_cnt || min_cnt == -1) {
            min_cnt = port->txq_used[i];
            min_qid = i;
        }
    }

    //选中对应的队列id
    port->txq_used[min_qid]++;
    tx->qid = min_qid;

    ovs_mutex_unlock(&port->txq_used_mutex);

    dpif_netdev_xps_revalidate_pmd(pmd, false);

    VLOG_DBG("Core %d: New TX queue ID %d for port \'%s\'.",
             pmd->core_id, tx->qid, netdev_get_name(tx->port->netdev));
    return min_qid;
}

static struct tx_port *
pmd_tnl_port_cache_lookup(const struct dp_netdev_pmd_thread *pmd,
                          odp_port_t port_no)
{
    return tx_port_lookup(&pmd->tnl_port_cache, port_no);
}

static struct tx_port *
pmd_send_port_cache_lookup(const struct dp_netdev_pmd_thread *pmd,
                           odp_port_t port_no)
{
    return tx_port_lookup(&pmd->send_port_cache, port_no);
}

//batch中规定的这组报文，统一封装隧道（attr中保存了隧道模板信息及出接口）
static int
push_tnl_action(const struct dp_netdev_pmd_thread *pmd,
                const struct nlattr *attr,
                struct dp_packet_batch *batch)
{
    struct tx_port *tun_port;
    const struct ovs_action_push_tnl *data;
    int err;

    data = nl_attr_get(attr);

    //搞清楚从那个netdev发送隧道报文（由那个port负责封装）
    tun_port = pmd_tnl_port_cache_lookup(pmd, data->tnl_port);
    //隧道接口已被删除
    if (!tun_port) {
        //隧道接口已被删除，或者不存在，参数有误
        err = -EINVAL;
        goto error;
    }
    err = netdev_push_header(tun_port->port->netdev, batch, data);//交netdev去封装隧道
    if (!err) {
        return 0;
    }
error:
    dp_packet_delete_batch(batch, true);
    return err;
}

static void
dp_execute_userspace_action(struct dp_netdev_pmd_thread *pmd,
                            struct dp_packet *packet, bool should_steal,
                            struct flow *flow, ovs_u128 *ufid,
                            struct ofpbuf *actions,
                            const struct nlattr *userdata)
{
    struct dp_packet_batch b;
    int error;

    ofpbuf_clear(actions);

    error = dp_netdev_upcall(pmd, packet, flow, NULL, ufid,
                             DPIF_UC_ACTION, userdata, actions,
                             NULL);//走上送流程
    if (!error || error == ENOSPC) {
        dp_packet_batch_init_packet(&b, packet);
        dp_netdev_execute_actions(pmd, &b, should_steal, flow,
                                  actions->data, actions->size);
    } else if (should_steal) {
        dp_packet_delete(packet);
    }
}

//完成单个报文的动作处理（需要datapath（可以理解为虚设备）参与)
static void
dp_execute_cb(void *aux_, struct dp_packet_batch *packets_,
              const struct nlattr *a, bool should_steal)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    struct dp_netdev_execute_aux *aux = aux_;
    uint32_t *depth = recirc_depth_get();
    struct dp_netdev_pmd_thread *pmd = aux->pmd;
    struct dp_netdev *dp = pmd->dp;
    int type = nl_attr_type(a);//检查动作类型
    struct tx_port *p;

    switch ((enum ovs_action_attr)type) {
    case OVS_ACTION_ATTR_OUTPUT://完成输出到指定接口的动作
        //自cache中取port
        p = pmd_send_port_cache_lookup(pmd, nl_attr_get_odp_port(a));
        if (OVS_LIKELY(p)) {
            struct dp_packet *packet;
            struct dp_packet_batch out;

            if (!should_steal) {
                dp_packet_batch_clone(&out, packets_);
                dp_packet_batch_reset_cutlen(packets_);
                packets_ = &out;
            }
            dp_packet_batch_apply_cutlen(packets_);

#ifdef DPDK_NETDEV
            if (OVS_UNLIKELY(!dp_packet_batch_is_empty(&p->output_pkts)
                             && packets_->packets[0]->source
                                != p->output_pkts.packets[0]->source)) {
                /* XXX: netdev-dpdk assumes that all packets in a single
                 *      output batch has the same source. Flush here to
                 *      avoid memory access issues. */
                dp_netdev_pmd_flush_output_on_port(pmd, p);
            }
#endif
            if (dp_packet_batch_size(&p->output_pkts)
                + dp_packet_batch_size(packets_) > NETDEV_MAX_BURST) {
                /* Flush here to avoid overflow. */
                dp_netdev_pmd_flush_output_on_port(pmd, p);
            }

            if (dp_packet_batch_is_empty(&p->output_pkts)) {
                pmd->n_output_batches++;
            }

            DP_PACKET_BATCH_FOR_EACH (i, packet, packets_) {
                p->output_pkts_rxqs[dp_packet_batch_size(&p->output_pkts)] =
                                                             pmd->ctx.last_rxq;
                dp_packet_batch_add(&p->output_pkts, packet);
            }
            return;
        }
        break;

    //隧道报文封装，由指定的port来处理，而port依据自已的隧道类型处理
    case OVS_ACTION_ATTR_TUNNEL_PUSH:
        if (should_steal) {
            /* We're requested to push tunnel header, but also we need to take
             * the ownership of these packets. Thus, we can avoid performing
             * the action, because the caller will not use the result anyway.
             * Just break to free the batch. */
            break;
        }
        dp_packet_batch_apply_cutlen(packets_);
        //加隧道后，不重查规则，按action继续走
        push_tnl_action(pmd, a, packets_);//执行push　tunnel动作
        return;

    case OVS_ACTION_ATTR_TUNNEL_POP://隧道报文解封装
        if (*depth < MAX_RECIRC_DEPTH) {
            struct dp_packet_batch *orig_packets_ = packets_;
            odp_port_t portno = nl_attr_get_odp_port(a);//由那个接口来解封装

            p = pmd_tnl_port_cache_lookup(pmd, portno);
            if (p) {
                struct dp_packet_batch tnl_pkt;

                if (!should_steal) {
                    dp_packet_batch_clone(&tnl_pkt, packets_);
                    packets_ = &tnl_pkt;
                    //原报文trun应用
                    dp_packet_batch_reset_cutlen(orig_packets_);
                }

                //被操作报文trun应用
                dp_packet_batch_apply_cutlen(packets_);

                //调用pop弹出隧道头
                netdev_pop_header(p->port->netdev, packets_);
                if (dp_packet_batch_is_empty(packets_)) {
                    return;
                }

                //将报文的入接口更改为portno
                struct dp_packet *packet;
                DP_PACKET_BATCH_FOR_EACH (i, packet, packets_) {
                    packet->md.in_port.odp_port = portno;
                }

                //增加递归深度，重查
                (*depth)++;
                dp_netdev_recirculate(pmd, packets_);
                (*depth)--;
                return;
            }
        }
        break;

    case OVS_ACTION_ATTR_USERSPACE:
    	//送userspace层面处理，执行upcall
        if (!fat_rwlock_tryrdlock(&dp->upcall_rwlock)) {
            struct dp_packet_batch *orig_packets_ = packets_;
            const struct nlattr *userdata;
            struct dp_packet_batch usr_pkt;
            struct ofpbuf actions;
            struct flow flow;
            ovs_u128 ufid;
            bool clone = false;

            userdata = nl_attr_find_nested(a, OVS_USERSPACE_ATTR_USERDATA);
            ofpbuf_init(&actions, 0);

            if (packets_->trunc) {
                if (!should_steal) {
                    dp_packet_batch_clone(&usr_pkt, packets_);
                    packets_ = &usr_pkt;
                    clone = true;
                    dp_packet_batch_reset_cutlen(orig_packets_);
                }

                //应用报文截短
                dp_packet_batch_apply_cutlen(packets_);
            }

            struct dp_packet *packet;
            DP_PACKET_BATCH_FOR_EACH (i, packet, packets_) {
                flow_extract(packet, &flow);
                dpif_flow_hash(dp->dpif, &flow, sizeof flow, &ufid);
                //走上送流程
                dp_execute_userspace_action(pmd, packet, should_steal, &flow,
                                            &ufid, &actions, userdata);
            }

            if (clone) {
                dp_packet_delete_batch(packets_, true);
            }

            ofpbuf_uninit(&actions);
            fat_rwlock_unlock(&dp->upcall_rwlock);

            return;
        }
        break;

    case OVS_ACTION_ATTR_RECIRC://规则要求跳表
        if (*depth < MAX_RECIRC_DEPTH) {
            struct dp_packet_batch recirc_pkts;

            if (!should_steal) {
               dp_packet_batch_clone(&recirc_pkts, packets_);
               packets_ = &recirc_pkts;
            }

            struct dp_packet *packet;
            DP_PACKET_BATCH_FOR_EACH (i, packet, packets_) {
                packet->md.recirc_id = nl_attr_get_u32(a);
            }

            (*depth)++;
            dp_netdev_recirculate(pmd, packets_);
            (*depth)--;

            return;
        }

        VLOG_WARN("Packet dropped. Max recirculation depth exceeded.");
        break;

    case OVS_ACTION_ATTR_CT: {
    	//连接跟踪动作执行，完成连接创建，分配nat资源
        const struct nlattr *b;
        bool force = false;
        bool commit = false;
        unsigned int left;
        uint16_t zone = 0;
        const char *helper = NULL;
        const uint32_t *setmark = NULL;
        const struct ovs_key_ct_labels *setlabel = NULL;
        struct nat_action_info_t nat_action_info;
        struct nat_action_info_t *nat_action_info_ref = NULL;
        bool nat_config = false;//是否配置了nat

        //遍历CT action中的小动作，填充配置的参数
        NL_ATTR_FOR_EACH_UNSAFE (b, left, nl_attr_get(a),
                                 nl_attr_get_size(a)) {
            enum ovs_ct_attr sub_type = nl_attr_type(b);

            //必要的几个参数设置，需要查下文档，看下面注释
            switch(sub_type) {
            case OVS_CT_ATTR_FORCE_COMMIT:
            	//force为true,则表示此报文方向必须为请求方向，如果为应答方向，则将连接无效掉
                force = true;
                /* fall through. */
            case OVS_CT_ATTR_COMMIT:
            	//commit为true,则表示容许此报文在链接跟踪表里添加新表项
                commit = true;
                break;
            case OVS_CT_ATTR_ZONE:
            	//指出zone编号
                zone = nl_attr_get_u16(b);
                break;
            case OVS_CT_ATTR_HELPER:
            	//用于alg的应用识别
                helper = nl_attr_get_string(b);
                break;
            case OVS_CT_ATTR_MARK:
                setmark = nl_attr_get(b);
                break;
            case OVS_CT_ATTR_LABELS:
                setlabel = nl_attr_get(b);
                break;
            case OVS_CT_ATTR_EVENTMASK:
                /* Silently ignored, as userspace datapath does not generate
                 * netlink events. */
                break;
            case OVS_CT_ATTR_TIMEOUT:
                /* Userspace datapath does not support customized timeout
                 * policy yet. */
                break;
            //填充nat_action_info结构体
            case OVS_CT_ATTR_NAT: {
                const struct nlattr *b_nest;
                unsigned int left_nest;
                bool ip_min_specified = false;//是否指定了ip下限
                bool proto_num_min_specified = false;//是否设置了port下限
                bool ip_max_specified = false;//是否设置了ip上限
                bool proto_num_max_specified = false;//是否设置了port上限
                memset(&nat_action_info, 0, sizeof nat_action_info);
                nat_action_info_ref = &nat_action_info;

                //遍历ct的配置信息，填充nat_action_info结构体
                NL_NESTED_FOR_EACH_UNSAFE (b_nest, left_nest, b) {
                    enum ovs_nat_attr sub_type_nest = nl_attr_type(b_nest);

                    switch (sub_type_nest) {
                    case OVS_NAT_ATTR_SRC:
                    case OVS_NAT_ATTR_DST:
                        nat_config = true;//配置了nat
                        nat_action_info.nat_action |=
                            ((sub_type_nest == OVS_NAT_ATTR_SRC)
                                ? NAT_ACTION_SRC : NAT_ACTION_DST);//设置做哪种nat，snat? or dnat?
                        break;
                    case OVS_NAT_ATTR_IP_MIN:
                        memcpy(&nat_action_info.min_addr,
                               nl_attr_get(b_nest),
                               nl_attr_get_size(b_nest));//设置地址池下限
                        ip_min_specified = true;
                        break;
                    case OVS_NAT_ATTR_IP_MAX:
                        memcpy(&nat_action_info.max_addr,
                               nl_attr_get(b_nest),
                               nl_attr_get_size(b_nest));//设置地址池上限
                        ip_max_specified = true;
                        break;
                    case OVS_NAT_ATTR_PROTO_MIN:
                        nat_action_info.min_port =
                            nl_attr_get_u16(b_nest);//设置port下限
                        proto_num_min_specified = true;
                        break;
                    case OVS_NAT_ATTR_PROTO_MAX:
                        nat_action_info.max_port =
                            nl_attr_get_u16(b_nest);//设置port上限
                        proto_num_max_specified = true;
                        break;
                    case OVS_NAT_ATTR_PERSISTENT:
                    case OVS_NAT_ATTR_PROTO_HASH:
                    case OVS_NAT_ATTR_PROTO_RANDOM:
                        break;
                    case OVS_NAT_ATTR_UNSPEC:
                    case __OVS_NAT_ATTR_MAX:
                        OVS_NOT_REACHED();
                    }
                }

                if (ip_min_specified && !ip_max_specified) {
                	//仅设置下限，未设置上限，则仅有一个ip
                    nat_action_info.max_addr = nat_action_info.min_addr;
                }
                if (proto_num_min_specified && !proto_num_max_specified) {
                	//如果仅设置下限，未设置上限，则仅有一个port
                    nat_action_info.max_port = nat_action_info.min_port;
                }

                //如果设置了port的上限或下限，则隐含启用了port转换
                if (proto_num_min_specified || proto_num_max_specified) {
                    if (nat_action_info.nat_action & NAT_ACTION_SRC) {
                        nat_action_info.nat_action |= NAT_ACTION_SRC_PORT;
                    } else if (nat_action_info.nat_action & NAT_ACTION_DST) {
                        nat_action_info.nat_action |= NAT_ACTION_DST_PORT;
                    }
                }
                break;
            }
            case OVS_CT_ATTR_UNSPEC:
            case __OVS_CT_ATTR_MAX:
                OVS_NOT_REACHED();
            }
        }

        /* We won't be able to function properly in this case, hence
         * complain loudly. */
        if (nat_config && !commit) {
        	//如果配置了nat，但未commit，则告警
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 5);
            VLOG_WARN_RL(&rl, "NAT specified without commit.");
        }

        //连接跟踪执行
        conntrack_execute(dp->conntrack, packets_, aux->flow->dl_type, force,
                          commit, zone, setmark, setlabel, aux->flow->tp_src,
                          aux->flow->tp_dst, helper, nat_action_info_ref,
                          pmd->ctx.now / 1000);
        break;
    }

    case OVS_ACTION_ATTR_METER:
        dp_netdev_run_meter(pmd->dp, packets_, nl_attr_get_u32(a),
                            pmd->ctx.now);
        break;

    //下面的action在上层函数中已执行
    case OVS_ACTION_ATTR_PUSH_VLAN:
    case OVS_ACTION_ATTR_POP_VLAN:
    case OVS_ACTION_ATTR_PUSH_MPLS:
    case OVS_ACTION_ATTR_POP_MPLS:
    case OVS_ACTION_ATTR_SET:
    case OVS_ACTION_ATTR_SET_MASKED:
    case OVS_ACTION_ATTR_SAMPLE:
    case OVS_ACTION_ATTR_HASH:
    case OVS_ACTION_ATTR_UNSPEC:
    case OVS_ACTION_ATTR_TRUNC:
    case OVS_ACTION_ATTR_PUSH_ETH:
    case OVS_ACTION_ATTR_POP_ETH:
    case OVS_ACTION_ATTR_CLONE:
    case OVS_ACTION_ATTR_PUSH_NSH:
    case OVS_ACTION_ATTR_POP_NSH:
    case OVS_ACTION_ATTR_CT_CLEAR:
    case OVS_ACTION_ATTR_CHECK_PKT_LEN:
    case __OVS_ACTION_ATTR_MAX:
        OVS_NOT_REACHED();
    }

    dp_packet_delete_batch(packets_, should_steal);
}

//执行动作
static void
dp_netdev_execute_actions(struct dp_netdev_pmd_thread *pmd,
                          struct dp_packet_batch *packets/*待按action处理的报文*/,
                          bool should_steal, const struct flow *flow,
                          const struct nlattr *actions, size_t actions_len)
{
    struct dp_netdev_execute_aux aux = { pmd, flow };

    odp_execute_actions(&aux, packets, should_steal, actions,
                        actions_len, dp_execute_cb);//dp_execute_cb是单个动作执行

}

struct dp_netdev_ct_dump {
    struct ct_dpif_dump_state up;
    struct conntrack_dump dump;
    struct conntrack *ct;
    struct dp_netdev *dp;
};

static int
dpif_netdev_ct_dump_start(struct dpif *dpif, struct ct_dpif_dump_state **dump_,
                          const uint16_t *pzone, int *ptot_bkts)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_ct_dump *dump;

    dump = xzalloc(sizeof *dump);
    dump->dp = dp;
    dump->ct = dp->conntrack;

    conntrack_dump_start(dp->conntrack, &dump->dump, pzone, ptot_bkts);

    *dump_ = &dump->up;

    return 0;
}

static int
dpif_netdev_ct_dump_next(struct dpif *dpif OVS_UNUSED,
                         struct ct_dpif_dump_state *dump_,
                         struct ct_dpif_entry *entry)
{
    struct dp_netdev_ct_dump *dump;

    INIT_CONTAINER(dump, dump_, up);

    return conntrack_dump_next(&dump->dump, entry);
}

static int
dpif_netdev_ct_dump_done(struct dpif *dpif OVS_UNUSED,
                         struct ct_dpif_dump_state *dump_)
{
    struct dp_netdev_ct_dump *dump;
    int err;

    INIT_CONTAINER(dump, dump_, up);

    err = conntrack_dump_done(&dump->dump);

    free(dump);

    return err;
}

static int
dpif_netdev_ct_flush(struct dpif *dpif, const uint16_t *zone,
                     const struct ct_dpif_tuple *tuple)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);

    if (tuple) {
        return conntrack_flush_tuple(dp->conntrack, tuple, zone ? *zone : 0);
    }
    return conntrack_flush(dp->conntrack, zone);
}

static int
dpif_netdev_ct_set_maxconns(struct dpif *dpif, uint32_t maxconns)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);

    return conntrack_set_maxconns(dp->conntrack, maxconns);
}

static int
dpif_netdev_ct_get_maxconns(struct dpif *dpif, uint32_t *maxconns)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);

    return conntrack_get_maxconns(dp->conntrack, maxconns);
}

static int
dpif_netdev_ct_get_nconns(struct dpif *dpif, uint32_t *nconns)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);

    return conntrack_get_nconns(dp->conntrack, nconns);
}

static int
dpif_netdev_ct_set_tcp_seq_chk(struct dpif *dpif, bool enabled)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);

    return conntrack_set_tcp_seq_chk(dp->conntrack, enabled);
}

static int
dpif_netdev_ct_get_tcp_seq_chk(struct dpif *dpif, bool *enabled)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    *enabled = conntrack_get_tcp_seq_chk(dp->conntrack);
    return 0;
}

static int
dpif_netdev_ipf_set_enabled(struct dpif *dpif, bool v6, bool enable)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    return ipf_set_enabled(conntrack_ipf_ctx(dp->conntrack), v6, enable);
}

static int
dpif_netdev_ipf_set_min_frag(struct dpif *dpif, bool v6, uint32_t min_frag)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    return ipf_set_min_frag(conntrack_ipf_ctx(dp->conntrack), v6, min_frag);
}

static int
dpif_netdev_ipf_set_max_nfrags(struct dpif *dpif, uint32_t max_frags)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    return ipf_set_max_nfrags(conntrack_ipf_ctx(dp->conntrack), max_frags);
}

/* Adjust this function if 'dpif_ipf_status' and 'ipf_status' were to
 * diverge. */
static int
dpif_netdev_ipf_get_status(struct dpif *dpif,
                           struct dpif_ipf_status *dpif_ipf_status)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    ipf_get_status(conntrack_ipf_ctx(dp->conntrack),
                   (struct ipf_status *) dpif_ipf_status);
    return 0;
}

static int
dpif_netdev_ipf_dump_start(struct dpif *dpif OVS_UNUSED,
                           struct ipf_dump_ctx **ipf_dump_ctx)
{
    return ipf_dump_start(ipf_dump_ctx);
}

static int
dpif_netdev_ipf_dump_next(struct dpif *dpif, void *ipf_dump_ctx, char **dump)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    return ipf_dump_next(conntrack_ipf_ctx(dp->conntrack), ipf_dump_ctx,
                         dump);
}

static int
dpif_netdev_ipf_dump_done(struct dpif *dpif OVS_UNUSED, void *ipf_dump_ctx)
{
    return ipf_dump_done(ipf_dump_ctx);

}

//走用户态转发的datapath
const struct dpif_class dpif_netdev_class = {
    "netdev",
    true,                       /* cleanup_required */
    dpif_netdev_init,
    dpif_netdev_enumerate,//枚举由此class创建的netdev
    dpif_netdev_port_open_type,
    dpif_netdev_open,//netdev类型的open回调
    dpif_netdev_close,
    dpif_netdev_destroy,
    dpif_netdev_run,//netdev类型的周期性工作(run函数）
    dpif_netdev_wait,
    dpif_netdev_get_stats,
    dpif_netdev_port_add,//netdev类的port添加
    dpif_netdev_port_del,
    dpif_netdev_port_set_config,
    dpif_netdev_port_query_by_number,
	//通过名称查找datapath中的port
    dpif_netdev_port_query_by_name,
    NULL,                       /* port_get_pid */
    dpif_netdev_port_dump_start,//遍历port开始
    dpif_netdev_port_dump_next,//获取下一个遍历位置
    dpif_netdev_port_dump_done,//遍历结束
    dpif_netdev_port_poll,
    dpif_netdev_port_poll_wait,
    dpif_netdev_flow_flush,
    dpif_netdev_flow_dump_create,
    dpif_netdev_flow_dump_destroy,
    dpif_netdev_flow_dump_thread_create,
    dpif_netdev_flow_dump_thread_destroy,
    dpif_netdev_flow_dump_next,
    dpif_netdev_operate,
    NULL,                       /* recv_set */
    NULL,                       /* handlers_set */
    dpif_netdev_set_config,
    dpif_netdev_queue_to_priority,
	//dpdk方式破坏了这一封装，没有提供recv
    NULL,                       /* recv */
    NULL,                       /* recv_wait */
    NULL,                       /* recv_purge */
    dpif_netdev_register_dp_purge_cb,
    dpif_netdev_register_upcall_cb,//upcall_cb回调注册函数
    dpif_netdev_enable_upcall,
    dpif_netdev_disable_upcall,
    dpif_netdev_get_datapath_version,
    dpif_netdev_ct_dump_start,
    dpif_netdev_ct_dump_next,
    dpif_netdev_ct_dump_done,
    dpif_netdev_ct_flush,
    dpif_netdev_ct_set_maxconns,
    dpif_netdev_ct_get_maxconns,
    dpif_netdev_ct_get_nconns,
    dpif_netdev_ct_set_tcp_seq_chk,
    dpif_netdev_ct_get_tcp_seq_chk,
    NULL,                       /* ct_set_limits */
    NULL,                       /* ct_get_limits */
    NULL,                       /* ct_del_limits */
    NULL,                       /* ct_set_timeout_policy */
    NULL,                       /* ct_get_timeout_policy */
    NULL,                       /* ct_del_timeout_policy */
    NULL,                       /* ct_timeout_policy_dump_start */
    NULL,                       /* ct_timeout_policy_dump_next */
    NULL,                       /* ct_timeout_policy_dump_done */
    NULL,                       /* ct_get_timeout_policy_name */
    dpif_netdev_ipf_set_enabled,
    dpif_netdev_ipf_set_min_frag,
    dpif_netdev_ipf_set_max_nfrags,
    dpif_netdev_ipf_get_status,
    dpif_netdev_ipf_dump_start,
    dpif_netdev_ipf_dump_next,
    dpif_netdev_ipf_dump_done,
    dpif_netdev_meter_get_features,
    dpif_netdev_meter_set,
    dpif_netdev_meter_get,
    dpif_netdev_meter_del,
};

static void
dpif_dummy_change_port_number(struct unixctl_conn *conn, int argc OVS_UNUSED,
                              const char *argv[], void *aux OVS_UNUSED)
{
    struct dp_netdev_port *port;
    struct dp_netdev *dp;
    odp_port_t port_no;

    ovs_mutex_lock(&dp_netdev_mutex);
    dp = shash_find_data(&dp_netdevs, argv[1]);
    if (!dp || !dpif_netdev_class_is_dummy(dp->class)) {
        ovs_mutex_unlock(&dp_netdev_mutex);
        unixctl_command_reply_error(conn, "unknown datapath or not a dummy");
        return;
    }
    ovs_refcount_ref(&dp->ref_cnt);
    ovs_mutex_unlock(&dp_netdev_mutex);

    ovs_mutex_lock(&dp->port_mutex);
    if (get_port_by_name(dp, argv[2], &port)) {
        unixctl_command_reply_error(conn, "unknown port");
        goto exit;
    }

    port_no = u32_to_odp(atoi(argv[3]));
    if (!port_no || port_no == ODPP_NONE) {
        unixctl_command_reply_error(conn, "bad port number");
        goto exit;
    }
    if (dp_netdev_lookup_port(dp, port_no)) {
        unixctl_command_reply_error(conn, "port number already in use");
        goto exit;
    }

    /* Remove port. */
    hmap_remove(&dp->ports, &port->node);
    reconfigure_datapath(dp);

    /* Reinsert with new port number. */
    port->port_no = port_no;
    hmap_insert(&dp->ports, &port->node, hash_port_no(port_no));
    reconfigure_datapath(dp);

    seq_change(dp->port_seq);
    unixctl_command_reply(conn, NULL);

exit:
    ovs_mutex_unlock(&dp->port_mutex);
    dp_netdev_unref(dp);
}

static void
dpif_dummy_register__(const char *type)
{
    struct dpif_class *class;

    class = xmalloc(sizeof *class);
    *class = dpif_netdev_class;
    class->type = xstrdup(type);
    dp_register_provider(class);
}

static void
dpif_dummy_override(const char *type)
{
    int error;

    /*
     * Ignore EAFNOSUPPORT to allow --enable-dummy=system with
     * a userland-only build.  It's useful for testsuite.
     */
    error = dp_unregister_provider(type);
    if (error == 0 || error == EAFNOSUPPORT) {
        dpif_dummy_register__(type);
    }
}

void
dpif_dummy_register(enum dummy_level level)
{
    if (level == DUMMY_OVERRIDE_ALL) {
        struct sset types;
        const char *type;

        sset_init(&types);
        dp_enumerate_types(&types);
        SSET_FOR_EACH (type, &types) {
            dpif_dummy_override(type);//强制使用netdev
        }
        sset_destroy(&types);
    } else if (level == DUMMY_OVERRIDE_SYSTEM) {
        dpif_dummy_override("system");//替换system为netdev回调
    }

    dpif_dummy_register__("dummy");//创建dummy为netdev回调

    unixctl_command_register("dpif-dummy/change-port-number",
                             "dp port new-number",
                             3, 3, dpif_dummy_change_port_number, NULL);
}

/* Datapath Classifier. */

static void
dpcls_subtable_destroy_cb(struct dpcls_subtable *subtable)
{
    cmap_destroy(&subtable->rules);
    ovsrcu_postpone(free, subtable->mf_masks);
    ovsrcu_postpone(free, subtable);
}

/* Initializes 'cls' as a classifier that initially contains no classification
 * rules. */
static void
dpcls_init(struct dpcls *cls)
{
    cmap_init(&cls->subtables_map);
    pvector_init(&cls->subtables);
}

static void
dpcls_destroy_subtable(struct dpcls *cls, struct dpcls_subtable *subtable)
{
    VLOG_DBG("Destroying subtable %p for in_port %d", subtable, cls->in_port);
    pvector_remove(&cls->subtables, subtable);
    cmap_remove(&cls->subtables_map, &subtable->cmap_node,
                subtable->mask.hash);
    ovsrcu_postpone(dpcls_subtable_destroy_cb, subtable);
}

/* Destroys 'cls'.  Rules within 'cls', if any, are not freed; this is the
 * caller's responsibility.
 * May only be called after all the readers have been terminated. */
static void
dpcls_destroy(struct dpcls *cls)
{
    if (cls) {
        struct dpcls_subtable *subtable;

        CMAP_FOR_EACH (subtable, cmap_node, &cls->subtables_map) {
            ovs_assert(cmap_count(&subtable->rules) == 0);
            dpcls_destroy_subtable(cls, subtable);
        }
        cmap_destroy(&cls->subtables_map);
        pvector_destroy(&cls->subtables);
    }
}

//创建一个dpcls子表
static struct dpcls_subtable *
dpcls_create_subtable(struct dpcls *cls, const struct netdev_flow_key *mask)
{
    struct dpcls_subtable *subtable;

    /* Need to add one. */
    subtable = xmalloc(sizeof *subtable
                       - sizeof subtable->mask.mf + mask->len);
    cmap_init(&subtable->rules);
    subtable->hit_cnt = 0;//命中数为０
    netdev_flow_key_clone(&subtable->mask, mask);//填充其对应的mask

    /* The count of bits in the mask defines the space required for masks.
     * Then call gen_masks() to create the appropriate masks, avoiding the cost
     * of doing runtime calculations. */
    uint32_t unit0 = count_1bits(mask->mf.map.bits[0]);
    uint32_t unit1 = count_1bits(mask->mf.map.bits[1]);
    subtable->mf_bits_set_unit0 = unit0;
    subtable->mf_bits_set_unit1 = unit1;
    subtable->mf_masks = xmalloc(sizeof(uint64_t) * (unit0 + unit1));
    netdev_flow_key_gen_masks(mask, subtable->mf_masks, unit0, unit1);

    /* Probe for a specialized generic lookup function. */
    subtable->lookup_func = dpcls_subtable_generic_probe(unit0, unit1);

    /* If not set, assign generic lookup. Generic works for any miniflow. */
    if (!subtable->lookup_func) {
        subtable->lookup_func = dpcls_subtable_lookup_generic;
    }

    cmap_insert(&cls->subtables_map, &subtable->cmap_node, mask->hash);
    /* Add the new subtable at the end of the pvector (with no hits yet) */
    pvector_insert(&cls->subtables, subtable, 0);//将其的指针加入subtables表
    VLOG_DBG("Creating %"PRIuSIZE". subtable %p for in_port %d",
             cmap_count(&cls->subtables_map), subtable, cls->in_port);
    pvector_publish(&cls->subtables);

    return subtable;
}

static inline struct dpcls_subtable *
dpcls_find_subtable(struct dpcls *cls, const struct netdev_flow_key *mask)
{
    struct dpcls_subtable *subtable;

    CMAP_FOR_EACH_WITH_HASH (subtable, cmap_node, mask->hash,
                             &cls->subtables_map) {
        if (netdev_flow_key_equal(&subtable->mask, mask)) {//找到了
            return subtable;
        }
    }
    return dpcls_create_subtable(cls, mask);//没有找到，重新创建一份
}


/* Periodically sort the dpcls subtable vectors according to hit counts */
//按命中次数对cls中的子表进行排序
static void
dpcls_sort_subtable_vector(struct dpcls *cls)
{
    struct pvector *pvec = &cls->subtables;
    struct dpcls_subtable *subtable;

    PVECTOR_FOR_EACH (subtable, pvec) {
        pvector_change_priority(pvec, subtable, subtable->hit_cnt);
        subtable->hit_cnt = 0;
    }
    pvector_publish(pvec);
}

static inline void
dp_netdev_pmd_try_optimize(struct dp_netdev_pmd_thread *pmd,
                           struct polled_queue *poll_list, int poll_cnt)
{
    struct dpcls *cls;
    uint64_t tot_idle = 0, tot_proc = 0;
    unsigned int pmd_load = 0;

    if (pmd->ctx.now > pmd->rxq_next_cycle_store) {
        uint64_t curr_tsc;
        struct pmd_auto_lb *pmd_alb = &pmd->dp->pmd_alb;
        if (pmd_alb->is_enabled && !pmd->isolated
            && (pmd->perf_stats.counters.n[PMD_CYCLES_ITER_IDLE] >=
                                       pmd->prev_stats[PMD_CYCLES_ITER_IDLE])
            && (pmd->perf_stats.counters.n[PMD_CYCLES_ITER_BUSY] >=
                                        pmd->prev_stats[PMD_CYCLES_ITER_BUSY]))
            {
            tot_idle = pmd->perf_stats.counters.n[PMD_CYCLES_ITER_IDLE] -
                       pmd->prev_stats[PMD_CYCLES_ITER_IDLE];
            tot_proc = pmd->perf_stats.counters.n[PMD_CYCLES_ITER_BUSY] -
                       pmd->prev_stats[PMD_CYCLES_ITER_BUSY];

            if (tot_proc) {
                pmd_load = ((tot_proc * 100) / (tot_idle + tot_proc));
            }

            if (pmd_load >= ALB_PMD_LOAD_THRESHOLD) {
                atomic_count_inc(&pmd->pmd_overloaded);
            } else {
                atomic_count_set(&pmd->pmd_overloaded, 0);
            }
        }

        pmd->prev_stats[PMD_CYCLES_ITER_IDLE] =
                        pmd->perf_stats.counters.n[PMD_CYCLES_ITER_IDLE];
        pmd->prev_stats[PMD_CYCLES_ITER_BUSY] =
                        pmd->perf_stats.counters.n[PMD_CYCLES_ITER_BUSY];

        /* Get the cycles that were used to process each queue and store. */
        for (unsigned i = 0; i < poll_cnt; i++) {
            uint64_t rxq_cyc_curr = dp_netdev_rxq_get_cycles(poll_list[i].rxq,
                                                        RXQ_CYCLES_PROC_CURR);
            dp_netdev_rxq_set_intrvl_cycles(poll_list[i].rxq, rxq_cyc_curr);
            dp_netdev_rxq_set_cycles(poll_list[i].rxq, RXQ_CYCLES_PROC_CURR,
                                     0);
        }
        curr_tsc = cycles_counter_update(&pmd->perf_stats);
        if (pmd->intrvl_tsc_prev) {
            /* There is a prev timestamp, store a new intrvl cycle count. */
            atomic_store_relaxed(&pmd->intrvl_cycles,
                                 curr_tsc - pmd->intrvl_tsc_prev);
        }
        pmd->intrvl_tsc_prev = curr_tsc;
        /* Start new measuring interval */
        pmd->rxq_next_cycle_store = pmd->ctx.now + PMD_RXQ_INTERVAL_LEN;
    }

    if (pmd->ctx.now > pmd->next_optimization) {
        /* Try to obtain the flow lock to block out revalidator threads.
         * If not possible, just try next time. */
        if (!ovs_mutex_trylock(&pmd->flow_mutex)) {
            /* Optimize each classifier */
            CMAP_FOR_EACH (cls, node, &pmd->classifiers) {
                dpcls_sort_subtable_vector(cls);
            }
            ovs_mutex_unlock(&pmd->flow_mutex);
            /* Start new measuring interval */
            pmd->next_optimization = pmd->ctx.now
                                     + DPCLS_OPTIMIZATION_INTERVAL;
        }
    }
}

/* Insert 'rule' into 'cls'. */
//将rule加入到cls中
static void
dpcls_insert(struct dpcls *cls, struct dpcls_rule *rule,
             const struct netdev_flow_key *mask)
{
    struct dpcls_subtable *subtable = dpcls_find_subtable(cls, mask);//返回mask对应的subtable

    /* Refer to subtable's mask, also for later removal. */
    rule->mask = &subtable->mask;
    cmap_insert(&subtable->rules, &rule->cmap_node, rule->flow.hash);
}

/* Removes 'rule' from 'cls', also destructing the 'rule'. */
static void
dpcls_remove(struct dpcls *cls, struct dpcls_rule *rule)
{
    struct dpcls_subtable *subtable;

    ovs_assert(rule->mask);

    /* Get subtable from reference in rule->mask. */
    INIT_CONTAINER(subtable, rule->mask, mask);
    if (cmap_remove(&subtable->rules, &rule->cmap_node, rule->flow.hash)
        == 0) {
        /* Delete empty subtable. */
        dpcls_destroy_subtable(cls, subtable);
        pvector_publish(&cls->subtables);
    }
}

/* Inner loop for mask generation of a unit, see netdev_flow_key_gen_masks. */
static inline void
netdev_flow_key_gen_mask_unit(uint64_t iter,
                              const uint64_t count,
                              uint64_t *mf_masks)
{
    int i;
    for (i = 0; i < count; i++) {
        uint64_t lowest_bit = (iter & -iter);
        iter &= ~lowest_bit;
        mf_masks[i] = (lowest_bit - 1);
    }
    /* Checks that count has covered all bits in the iter bitmap. */
    ovs_assert(iter == 0);
}

/* Generate a mask for each block in the miniflow, based on the bits set. This
 * allows easily masking packets with the generated array here, without
 * calculations. This replaces runtime-calculating the masks.
 * @param key The table to generate the mf_masks for
 * @param mf_masks Pointer to a u64 array of at least *mf_bits* in size
 * @param mf_bits_total Number of bits set in the whole miniflow (both units)
 * @param mf_bits_unit0 Number of bits set in unit0 of the miniflow
 */
void
netdev_flow_key_gen_masks(const struct netdev_flow_key *tbl,
                          uint64_t *mf_masks,
                          const uint32_t mf_bits_u0,
                          const uint32_t mf_bits_u1)
{
    uint64_t iter_u0 = tbl->mf.map.bits[0];
    uint64_t iter_u1 = tbl->mf.map.bits[1];

    netdev_flow_key_gen_mask_unit(iter_u0, mf_bits_u0, &mf_masks[0]);
    netdev_flow_key_gen_mask_unit(iter_u1, mf_bits_u1, &mf_masks[mf_bits_u0]);
}

/* Returns true if 'target' satisfies 'key' in 'mask', that is, if each 1-bit
 * in 'mask' the values in 'key' and 'target' are the same. */
//取出规则掩码，与target进行与运算，检查是否与规则要求的一致？
bool
dpcls_rule_matches_key(const struct dpcls_rule *rule,
                       const struct netdev_flow_key *target)
{
    const uint64_t *keyp = miniflow_get_values(&rule->flow.mf);//规则中配置的值
    const uint64_t *maskp = miniflow_get_values(&rule->mask->mf);//规则要求的掩码
    uint64_t value;

    NETDEV_FLOW_KEY_FOR_EACH_IN_FLOWMAP(value, target, rule->flow.mf.map) {//遍历规则的mf.map，与target进行比对
        if (OVS_UNLIKELY((value & *maskp++) != *keyp++)) {
            return false;
        }
    }
    return true;
}

/* For each miniflow in 'keys' performs a classifier lookup writing the result
 * into the corresponding slot in 'rules'.  If a particular entry in 'keys' is
 * NULL it is skipped.
 *
 * This function is optimized for use in the userspace datapath and therefore
 * does not implement a lot of features available in the standard
 * classifier_lookup() function.  Specifically, it does not implement
 * priorities, instead returning any rule which matches the flow.
 *
 * Returns true if all miniflows found a corresponding rule. */
//在cls中查找规则，如果返回true，则所有规则被命中，否则返回false
static bool
dpcls_lookup(struct dpcls *cls, const struct netdev_flow_key *keys[],
             struct dpcls_rule **rules, const size_t cnt,
             int *num_lookups_p)
{
    /* The received 'cnt' miniflows are the search-keys that will be processed
     * to find a matching entry into the available subtables.
     * The number of bits in map_type is equal to NETDEV_MAX_BURST. */
#define MAP_BITS (sizeof(uint32_t) * CHAR_BIT)
    BUILD_ASSERT_DECL(MAP_BITS >= NETDEV_MAX_BURST);

    struct dpcls_subtable *subtable;
    uint32_t keys_map = TYPE_MAXIMUM(uint32_t); /* Set all bits. */

    if (cnt != MAP_BITS) {
        keys_map >>= MAP_BITS - cnt; /* Clear extra bits. */
    }
    memset(rules, 0, cnt * sizeof *rules);

    int lookups_match = 0, subtable_pos = 1;
    uint32_t found_map;

    /* The Datapath classifier - aka dpcls - is composed of subtables.
     * Subtables are dynamically created as needed when new rules are inserted.
     * Each subtable collects rules with matches on a specific subset of packet
     * fields as defined by the subtable's mask.  We proceed to process every
     * search-key against each subtable, but when a match is found for a
     * search-key, the search for that key can stop because the rules are
     * non-overlapping. */
    PVECTOR_FOR_EACH (subtable, &cls->subtables) {
        /* Call the subtable specific lookup function. */
        found_map = subtable->lookup_func(subtable, keys_map, keys, rules);

        /* Count the number of subtables searched for this packet match. This
         * estimates the "spread" of subtables looked at per matched packet. */
        uint32_t pkts_matched = count_1bits(found_map);
        lookups_match += pkts_matched * subtable_pos;

        /* Clear the found rules, and return early if all packets are found. */
        keys_map &= ~found_map;
        if (!keys_map) {
            if (num_lookups_p) {
                *num_lookups_p = lookups_match;
            }
            return true;
        }
        subtable_pos++;
    }

    if (num_lookups_p) {
        *num_lookups_p = lookups_match;
    }
    return false;
}
