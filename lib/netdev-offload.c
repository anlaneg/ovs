/*
 * Copyright (c) 2008 - 2014, 2016, 2017 Nicira, Inc.
 * Copyright (c) 2019 Samsung Electronics Co.,Ltd.
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
#include "netdev-offload.h"

#include <errno.h>
#include <inttypes.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "cmap.h"
#include "coverage.h"
#include "dpif.h"
#include "dp-packet.h"
#include "openvswitch/dynamic-string.h"
#include "fatal-signal.h"
#include "hash.h"
#include "openvswitch/list.h"
#include "netdev-offload-provider.h"
#include "netdev-provider.h"
#include "netdev-vport.h"
#include "odp-netlink.h"
#include "openflow/openflow.h"
#include "packets.h"
#include "openvswitch/ofp-print.h"
#include "openvswitch/poll-loop.h"
#include "seq.h"
#include "openvswitch/shash.h"
#include "smap.h"
#include "socket-util.h"
#include "sset.h"
#include "svec.h"
#include "openvswitch/vlog.h"
#include "flow.h"
#include "util.h"
#ifdef __linux__
#include "tc.h"
#endif

VLOG_DEFINE_THIS_MODULE(netdev_offload);


static bool netdev_flow_api_enabled = false;

#define DEFAULT_OFFLOAD_THREAD_NB 1
#define MAX_OFFLOAD_THREAD_NB 10

static unsigned int offload_thread_nb = DEFAULT_OFFLOAD_THREAD_NB;
DEFINE_EXTERN_PER_THREAD_DATA(netdev_offload_thread_id, OVSTHREAD_ID_UNSET);

/* Protects 'netdev_flow_apis'.  */
static struct ovs_mutex netdev_flow_api_provider_mutex = OVS_MUTEX_INITIALIZER;

/* Contains 'struct netdev_registered_flow_api's. */
static struct cmap netdev_flow_apis = CMAP_INITIALIZER;

struct netdev_registered_flow_api {
    struct cmap_node cmap_node; /* In 'netdev_flow_apis', by flow_api->type. */
    const struct netdev_flow_api *flow_api;

    /* Number of references: one for the flow_api itself and one for every
     * instance of the netdev that uses it. */
    struct ovs_refcount refcnt;
};

//检查flow api是否已注册
static struct netdev_registered_flow_api *
netdev_lookup_flow_api(const char *type)
{
    struct netdev_registered_flow_api *rfa;
    CMAP_FOR_EACH_WITH_HASH (rfa, cmap_node, hash_string(type, 0),
                             &netdev_flow_apis) {
        if (!strcmp(type, rfa->flow_api->type)) {
            return rfa;
        }
    }
    return NULL;
}

/* Registers a new netdev flow api provider. */
//注册netdev的offload流操作函数
int
netdev_register_flow_api_provider(const struct netdev_flow_api *new_flow_api)
    OVS_EXCLUDED(netdev_flow_api_provider_mutex)
{
    int error = 0;

    //必须提供init_flow_api
    if (!new_flow_api->init_flow_api) {
        VLOG_WARN("attempted to register invalid flow api provider: %s",
                   new_flow_api->type);
        error = EINVAL;
    }

    ovs_mutex_lock(&netdev_flow_api_provider_mutex);
    if (netdev_lookup_flow_api(new_flow_api->type)) {
        //此flow api已注册，报错
        VLOG_WARN("attempted to register duplicate flow api provider: %s",
                   new_flow_api->type);
        error = EEXIST;
    } else {
        //不存在，申请rfa并将其加入到netdev_flow_apis中
        struct netdev_registered_flow_api *rfa;

        rfa = xmalloc(sizeof *rfa);
        cmap_insert(&netdev_flow_apis, &rfa->cmap_node,
                    hash_string(new_flow_api->type, 0));
        rfa->flow_api = new_flow_api;
        ovs_refcount_init(&rfa->refcnt);
        VLOG_DBG("netdev: flow API '%s' registered.", new_flow_api->type);
    }
    ovs_mutex_unlock(&netdev_flow_api_provider_mutex);

    return error;
}

/* Unregisters a netdev flow api provider.  'type' must have been previously
 * registered and not currently be in use by any netdevs.  After unregistration
 * netdev flow api of that type cannot be used for netdevs.  (However, the
 * provider may still be accessible from other threads until the next RCU grace
 * period, so the caller must not free or re-register the same netdev_flow_api
 * until that has passed.) */
int
netdev_unregister_flow_api_provider(const char *type)
    OVS_EXCLUDED(netdev_flow_api_provider_mutex)
{
    struct netdev_registered_flow_api *rfa;
    int error;

    ovs_mutex_lock(&netdev_flow_api_provider_mutex);
    rfa = netdev_lookup_flow_api(type);
    if (!rfa) {
        VLOG_WARN("attempted to unregister a flow api provider that is not "
                  "registered: %s", type);
        error = EAFNOSUPPORT;
    } else if (ovs_refcount_unref(&rfa->refcnt) != 1) {
        ovs_refcount_ref(&rfa->refcnt);
        VLOG_WARN("attempted to unregister in use flow api provider: %s",
                  type);
        error = EBUSY;
    } else  {
        cmap_remove(&netdev_flow_apis, &rfa->cmap_node,
                    hash_string(rfa->flow_api->type, 0));
        ovsrcu_postpone(free, rfa);
        error = 0;
    }
    ovs_mutex_unlock(&netdev_flow_api_provider_mutex);

    return error;
}

//检查两个netdev是否使用相同的flow_api
bool
netdev_flow_api_equals(const struct netdev *netdev1,
                       const struct netdev *netdev2)
{
    const struct netdev_flow_api *netdev_flow_api1 =
        ovsrcu_get(const struct netdev_flow_api *, &netdev1->flow_api);
    const struct netdev_flow_api *netdev_flow_api2 =
        ovsrcu_get(const struct netdev_flow_api *, &netdev2->flow_api);

    return netdev_flow_api1 == netdev_flow_api2;
}

//为netdev尝试关联其对应的flow_api
static int
netdev_assign_flow_api(struct netdev *netdev)
{
    struct netdev_registered_flow_api *rfa;

    //遍历所有flow api,如果某flow api可成功初始化此netdev，则采用此方式下发flow
    CMAP_FOR_EACH (rfa, cmap_node, &netdev_flow_apis) {
        if (!rfa->flow_api->init_flow_api(netdev)) {
            ovs_refcount_ref(&rfa->refcnt);
            ovsrcu_set(&netdev->flow_api, rfa->flow_api);
            VLOG_INFO("%s: Assigned flow API '%s'.",
                      netdev_get_name(netdev), rfa->flow_api->type);
            return 0;
        }
        VLOG_DBG("%s: flow API '%s' is not suitable.",
                 netdev_get_name(netdev), rfa->flow_api->type);
    }
    VLOG_INFO("%s: No suitable flow API found.", netdev_get_name(netdev));

    return -1;
}

int
netdev_flow_flush(struct netdev *netdev)
{
    const struct netdev_flow_api *flow_api =
        ovsrcu_get(const struct netdev_flow_api *, &netdev->flow_api);

    return (flow_api && flow_api->flow_flush)
           ? flow_api->flow_flush(netdev)
           : EOPNOTSUPP;
}

int
netdev_flow_dump_create(struct netdev *netdev, struct netdev_flow_dump **dump,
                        bool terse)
{
    /*取此netdev的flow_api函数*/
    const struct netdev_flow_api *flow_api =
        ovsrcu_get(const struct netdev_flow_api *, &netdev->flow_api);

    /*针对此netdev创建flow dump的context*/
    return (flow_api && flow_api->flow_dump_create)
           ? flow_api->flow_dump_create(netdev, dump, terse)
           : EOPNOTSUPP;
}

int
netdev_flow_dump_destroy(struct netdev_flow_dump *dump)
{
    const struct netdev_flow_api *flow_api =
        ovsrcu_get(const struct netdev_flow_api *, &dump->netdev->flow_api);

    return (flow_api && flow_api->flow_dump_destroy)
           ? flow_api->flow_dump_destroy(dump)
           : EOPNOTSUPP;
}

/*dump已经offload的flow*/
bool
netdev_flow_dump_next(struct netdev_flow_dump *dump, struct match *match/*出参，匹配信息*/,
                      struct nlattr **actions/*出参，action信息*/, struct dpif_flow_stats *stats/*出参，flow统计信息*/,
                      struct dpif_flow_attrs *attrs/*出参，flow属性信息*/, ovs_u128 *ufid/*出参，flow唯一标实*/,
                      struct ofpbuf *rbuffer, struct ofpbuf *wbuffer/*辅助用可写buffer*/)
{
    const struct netdev_flow_api *flow_api =
        ovsrcu_get(const struct netdev_flow_api *, &dump->netdev->flow_api);

    return (flow_api && flow_api->flow_dump_next)
           ? flow_api->flow_dump_next(dump, match, actions, stats, attrs,
                                      ufid, rbuffer, wbuffer)
           : false;
}

//向硬件下发需要执行的flow
int
netdev_flow_put(struct netdev *netdev, struct match *match/*下发的match字段*/,
                struct nlattr *actions/*下发的actions字段*/, size_t act_len/*action大小*/,
                const ovs_u128 *ufid/*用于唯一标识规则*/, struct offload_info *info/*卸载相关信息*/,
                struct dpif_flow_stats *stats)
{
    //交给各netdev->flow_api去实现(例如通过tc执行flow下发）
    const struct netdev_flow_api *flow_api =
        ovsrcu_get(const struct netdev_flow_api *, &netdev->flow_api);

    return (flow_api && flow_api->flow_put)
           ? flow_api->flow_put(netdev, match, actions, act_len, ufid,
                                info, stats)
           : EOPNOTSUPP;
}

int
netdev_hw_miss_packet_recover(struct netdev *netdev,
                              struct dp_packet *packet)
{
    const struct netdev_flow_api *flow_api =
        ovsrcu_get(const struct netdev_flow_api *, &netdev->flow_api);

    return (flow_api && flow_api->hw_miss_packet_recover)
            ? flow_api->hw_miss_packet_recover(netdev, packet)
            : EOPNOTSUPP;
}

int
netdev_flow_get(struct netdev *netdev, struct match *match,
                struct nlattr **actions, const ovs_u128 *ufid,
                struct dpif_flow_stats *stats,
                struct dpif_flow_attrs *attrs, struct ofpbuf *buf)
{
    const struct netdev_flow_api *flow_api =
        ovsrcu_get(const struct netdev_flow_api *, &netdev->flow_api);

    return (flow_api && flow_api->flow_get)
           ? flow_api->flow_get(netdev, match, actions, ufid,
                                stats, attrs, buf)
           : EOPNOTSUPP;
}

int
netdev_flow_del(struct netdev *netdev, const ovs_u128 *ufid,
                struct dpif_flow_stats *stats)
{
    const struct netdev_flow_api *flow_api =
        ovsrcu_get(const struct netdev_flow_api *, &netdev->flow_api);

    return (flow_api && flow_api->flow_del)
           ? flow_api->flow_del(netdev, ufid, stats)
           : EOPNOTSUPP;
}

//按不同接口初始化flow api
int
netdev_flow_get_n_flows(struct netdev *netdev, uint64_t *n_flows)
{
    const struct netdev_flow_api *flow_api =
        ovsrcu_get(const struct netdev_flow_api *, &netdev->flow_api);

    return (flow_api && flow_api->flow_get_n_flows)
           ? flow_api->flow_get_n_flows(netdev, n_flows)
           : EOPNOTSUPP;
}

int
netdev_init_flow_api(struct netdev *netdev)
{
    if (!netdev_is_flow_api_enabled()) {
    	//未开启offload,不初始化
        return EOPNOTSUPP;
    }

    if (ovsrcu_get(const struct netdev_flow_api *, &netdev->flow_api)) {
        return 0;
    }

    //如果为此netdev关联flow api失败，则返回不支持
    if (netdev_assign_flow_api(netdev)) {
        return EOPNOTSUPP;
    }

    return 0;
}

void
netdev_uninit_flow_api(struct netdev *netdev)
{
    struct netdev_registered_flow_api *rfa;
    const struct netdev_flow_api *flow_api =
            ovsrcu_get(const struct netdev_flow_api *, &netdev->flow_api);

    if (!flow_api) {
        return;
    }

    if (flow_api->uninit_flow_api) {
        flow_api->uninit_flow_api(netdev);
    }

    ovsrcu_set(&netdev->flow_api, NULL);
    rfa = netdev_lookup_flow_api(flow_api->type);
    ovs_refcount_unref(&rfa->refcnt);
}

/*取netdev对应的block id*/
uint32_t
netdev_get_block_id(struct netdev *netdev)
{
    const struct netdev_class *class = netdev->netdev_class;

    return (class->get_block_id
            ? class->get_block_id(netdev)
            : 0);
}

/*
 * Get the value of the hw info parameter specified by type.
 * Returns the value on success (>= 0). Returns -1 on failure.
 */
int
netdev_get_hw_info(struct netdev *netdev, int type)
{
    int val = -1;

    switch (type) {
    case HW_INFO_TYPE_OOR:
        val = netdev->hw_info.oor;
        break;
    case HW_INFO_TYPE_PEND_COUNT:
        val = netdev->hw_info.pending_count;
        break;
    case HW_INFO_TYPE_OFFL_COUNT:
        val = netdev->hw_info.offload_count;
        break;
    default:
        break;
    }

    return val;
}

/*
 * Set the value of the hw info parameter specified by type.
 */
void
netdev_set_hw_info(struct netdev *netdev, int type, int val)
{
    switch (type) {
    case HW_INFO_TYPE_OOR:
        if (val == 0) {
            VLOG_DBG("Offload rebalance: netdev: %s is not OOR", netdev->name);
        }
        netdev->hw_info.oor = val;
        break;
    case HW_INFO_TYPE_PEND_COUNT:
        netdev->hw_info.pending_count = val;
        break;
    case HW_INFO_TYPE_OFFL_COUNT:
        netdev->hw_info.offload_count = val;
        break;
    default:
        break;
    }
}

/* Protects below port hashmaps. */
static struct ovs_rwlock netdev_hmap_rwlock = OVS_RWLOCK_INITIALIZER;

//port_no到netdev的映射
static struct hmap port_to_netdev OVS_GUARDED_BY(netdev_hmap_rwlock)
    = HMAP_INITIALIZER(&port_to_netdev);
//ifindex到netdev的映射
static struct hmap ifindex_to_port OVS_GUARDED_BY(netdev_hmap_rwlock)
    = HMAP_INITIALIZER(&ifindex_to_port);

struct port_to_netdev_data {
    struct hmap_node portno_node; /* By (dpif_type, dpif_port.port_no). */
    struct hmap_node ifindex_node; /* By (dpif_type, ifindex). */
    struct netdev *netdev;
    struct dpif_port dpif_port;
    int ifindex;
};

/*
 * Find if any netdev is in OOR state. Return true if there's at least
 * one netdev that's in OOR state; otherwise return false.
 */
bool
netdev_any_oor(void)
    OVS_EXCLUDED(netdev_hmap_rwlock)
{
    struct port_to_netdev_data *data;
    bool oor = false;

    ovs_rwlock_rdlock(&netdev_hmap_rwlock);
    HMAP_FOR_EACH (data, portno_node, &port_to_netdev) {
        struct netdev *dev = data->netdev;

        if (dev->hw_info.oor) {
            oor = true;
            break;
        }
    }
    ovs_rwlock_unlock(&netdev_hmap_rwlock);

    return oor;
}

bool
netdev_is_flow_api_enabled(void)
{
    return netdev_flow_api_enabled;
}

unsigned int
netdev_offload_thread_nb(void)
{
    return offload_thread_nb;
}

unsigned int
netdev_offload_ufid_to_thread_id(const ovs_u128 ufid)
{
    uint32_t ufid_hash;

    if (netdev_offload_thread_nb() == 1) {
        return 0;
    }

    ufid_hash = hash_words64_inline(
            (const uint64_t [2]){ ufid.u64.lo,
                                  ufid.u64.hi }, 2, 1);
    return ufid_hash % netdev_offload_thread_nb();
}

unsigned int
netdev_offload_thread_init(void)
{
    static atomic_count next_id = ATOMIC_COUNT_INIT(0);
    bool thread_is_hw_offload;
    bool thread_is_rcu;

    thread_is_hw_offload = !strncmp(get_subprogram_name(),
                                    "hw_offload", strlen("hw_offload"));
    thread_is_rcu = !strncmp(get_subprogram_name(), "urcu", strlen("urcu"));

    /* Panic if any other thread besides offload and RCU tries
     * to initialize their thread ID. */
    ovs_assert(thread_is_hw_offload || thread_is_rcu);

    if (*netdev_offload_thread_id_get() == OVSTHREAD_ID_UNSET) {
        unsigned int id;

        if (thread_is_rcu) {
            /* RCU will compete with other threads for shared object access.
             * Reclamation functions using a thread ID must be thread-safe.
             * For that end, and because RCU must consider all potential shared
             * objects anyway, its thread-id can be whichever, so return 0.
             */
            id = 0;
        } else {
            /* Only the actual offload threads have their own ID. */
            id = atomic_count_inc(&next_id);
        }
        /* Panic if any offload thread is getting a spurious ID. */
        ovs_assert(id < netdev_offload_thread_nb());
        return *netdev_offload_thread_id_get() = id;
    } else {
        return *netdev_offload_thread_id_get();
    }
}

void
netdev_ports_flow_flush(const char *dpif_type)
{
    struct port_to_netdev_data *data;

    ovs_rwlock_rdlock(&netdev_hmap_rwlock);
    HMAP_FOR_EACH (data, portno_node, &port_to_netdev) {
        if (netdev_get_dpif_type(data->netdev) == dpif_type) {
            netdev_flow_flush(data->netdev);
        }
    }
    ovs_rwlock_unlock(&netdev_hmap_rwlock);
}

void
netdev_ports_traverse(const char *dpif_type,
                      bool (*cb)(struct netdev *, odp_port_t, void *),
                      void *aux)
{
    struct port_to_netdev_data *data;

    ovs_rwlock_rdlock(&netdev_hmap_rwlock);
    HMAP_FOR_EACH (data, portno_node, &port_to_netdev) {
        if (netdev_get_dpif_type(data->netdev) == dpif_type) {
            if (cb(data->netdev, data->dpif_port.port_no, aux)) {
                break;
            }
        }
    }
    ovs_rwlock_unlock(&netdev_hmap_rwlock);
}

//针对每个port创建一组dump,并返回（port需要为dpif_class类型）
struct netdev_flow_dump **
netdev_ports_flow_dump_create(const char *dpif_type, int *ports/*出参，dumps数组长度（与port数相等）*/, bool terse)
{
    struct port_to_netdev_data *data;
    struct netdev_flow_dump **dumps;
    int count = 0;
    int i = 0;

    ovs_rwlock_rdlock(&netdev_hmap_rwlock);

    //计算有多少个port(需要为指定的datapath)
    HMAP_FOR_EACH (data, portno_node, &port_to_netdev) {
        if (netdev_get_dpif_type(data->netdev) == dpif_type) {
            count++;
        }
    }

    //针对每个port申请一个dumps
    dumps = count ? xzalloc(sizeof *dumps * count) : NULL;

    //针对每个port创建一个flow dump context
    HMAP_FOR_EACH (data, portno_node, &port_to_netdev) {
        if (netdev_get_dpif_type(data->netdev) == dpif_type) {
            if (netdev_flow_dump_create(data->netdev, &dumps[i], terse)) {
                continue;
            }

            dumps[i]->port = data->dpif_port.port_no;
            i++;
        }
    }
    ovs_rwlock_unlock(&netdev_hmap_rwlock);

    *ports = i;
    return dumps;
}

/*通过ufid移除datapath规则*/
int
netdev_ports_flow_del(const char *dpif_type, const ovs_u128 *ufid,
                      struct dpif_flow_stats *stats)
{
    struct port_to_netdev_data *data;

    ovs_rwlock_rdlock(&netdev_hmap_rwlock);
    HMAP_FOR_EACH (data, portno_node, &port_to_netdev) {
        /*datapath类型*/
        if (netdev_get_dpif_type(data->netdev) == dpif_type
                /*按照ufid移除datapath规则*/
            && !netdev_flow_del(data->netdev, ufid, stats)) {
            ovs_rwlock_unlock(&netdev_hmap_rwlock);
            return 0;
        }
    }
    ovs_rwlock_unlock(&netdev_hmap_rwlock);

    return ENOENT;
}

int
netdev_ports_flow_get(const char *dpif_type, struct match *match,
                      struct nlattr **actions, const ovs_u128 *ufid,
                      struct dpif_flow_stats *stats,
                      struct dpif_flow_attrs *attrs, struct ofpbuf *buf)
{
    struct port_to_netdev_data *data;

    ovs_rwlock_rdlock(&netdev_hmap_rwlock);
    HMAP_FOR_EACH (data, portno_node, &port_to_netdev) {
        if (netdev_get_dpif_type(data->netdev) == dpif_type
            && !netdev_flow_get(data->netdev, match, actions,
                                ufid, stats, attrs, buf)) {
            ovs_rwlock_unlock(&netdev_hmap_rwlock);
            return 0;
        }
    }
    ovs_rwlock_unlock(&netdev_hmap_rwlock);
    return ENOENT;
}

static uint32_t
netdev_ports_hash(odp_port_t port, const char *dpif_type)
{
    return hash_int(odp_to_u32(port), hash_pointer(dpif_type, 0));
}

//给定port_no,获取netdev
static struct port_to_netdev_data *
netdev_ports_lookup(odp_port_t port_no, const char *dpif_type)
    OVS_REQ_RDLOCK(netdev_hmap_rwlock)
{
    struct port_to_netdev_data *data;

    HMAP_FOR_EACH_WITH_HASH (data, portno_node,
                             netdev_ports_hash(port_no, dpif_type),
                             &port_to_netdev/*记录port_no到netdev的映射*/) {
        if (netdev_get_dpif_type(data->netdev) == dpif_type
            && data->dpif_port.port_no == port_no) {
            return data;
        }
    }
    return NULL;
}

int
netdev_ports_insert(struct netdev *netdev, struct dpif_port *dpif_port)
{
    const char *dpif_type = netdev_get_dpif_type(netdev);
    struct port_to_netdev_data *data;
    int ifindex = netdev_get_ifindex(netdev);

    ovs_assert(dpif_type);

    ovs_rwlock_wrlock(&netdev_hmap_rwlock);
    if (netdev_ports_lookup(dpif_port->port_no, dpif_type)) {
    	//指定的port已存在
        ovs_rwlock_unlock(&netdev_hmap_rwlock);
        return EEXIST;
    }

    data = xzalloc(sizeof *data);
    data->netdev = netdev_ref(netdev);
    dpif_port_clone(&data->dpif_port, dpif_port);

    if (ifindex >= 0) {
        data->ifindex = ifindex;
        hmap_insert(&ifindex_to_port, &data->ifindex_node, ifindex);
    } else {
        data->ifindex = -1;
    }

    hmap_insert(&port_to_netdev, &data->portno_node,
                netdev_ports_hash(dpif_port->port_no, dpif_type));
    ovs_rwlock_unlock(&netdev_hmap_rwlock);

    //初始化netdev的flow api(例如tc情况下创建ingress队列）
    netdev_init_flow_api(netdev);

    return 0;
}

//通过port_no获取netdev
struct netdev *
netdev_ports_get(odp_port_t port_no, const char *dpif_type)
{
    struct port_to_netdev_data *data;
    struct netdev *ret = NULL;

    ovs_rwlock_rdlock(&netdev_hmap_rwlock);
    data = netdev_ports_lookup(port_no, dpif_type);
    if (data) {
        ret = netdev_ref(data->netdev);
    }
    ovs_rwlock_unlock(&netdev_hmap_rwlock);

    return ret;
}

int
netdev_ports_remove(odp_port_t port_no, const char *dpif_type)
{
    struct port_to_netdev_data *data;
    int ret = ENOENT;

    ovs_rwlock_wrlock(&netdev_hmap_rwlock);
    data = netdev_ports_lookup(port_no, dpif_type);
    if (data) {
        dpif_port_destroy(&data->dpif_port);
        netdev_close(data->netdev); /* unref and possibly close */
        hmap_remove(&port_to_netdev, &data->portno_node);
        if (data->ifindex >= 0) {
            hmap_remove(&ifindex_to_port, &data->ifindex_node);
        }
        free(data);
        ret = 0;
    }
    ovs_rwlock_unlock(&netdev_hmap_rwlock);

    return ret;
}

int
netdev_ports_get_n_flows(const char *dpif_type, odp_port_t port_no,
                         uint64_t *n_flows)
{
    struct port_to_netdev_data *data;
    int ret = EOPNOTSUPP;

    ovs_rwlock_rdlock(&netdev_hmap_rwlock);
    data = netdev_ports_lookup(port_no, dpif_type);
    if (data) {
        uint64_t thread_n_flows[MAX_OFFLOAD_THREAD_NB] = {0};
        unsigned int tid;

        ret = netdev_flow_get_n_flows(data->netdev, thread_n_flows);
        *n_flows = 0;
        if (!ret) {
            for (tid = 0; tid < netdev_offload_thread_nb(); tid++) {
                *n_flows += thread_n_flows[tid];
            }
        }
    }
    ovs_rwlock_unlock(&netdev_hmap_rwlock);
    return ret;
}

odp_port_t
netdev_ifindex_to_odp_port(int ifindex)
{
    struct port_to_netdev_data *data;
    odp_port_t ret = 0;

    ovs_rwlock_rdlock(&netdev_hmap_rwlock);
    HMAP_FOR_EACH_WITH_HASH (data, ifindex_node, ifindex, &ifindex_to_port) {
        if (data->ifindex == ifindex) {
            ret = data->dpif_port.port_no;
            break;
        }
    }
    ovs_rwlock_unlock(&netdev_hmap_rwlock);

    return ret;
}

//默认rebalance的策略为False
static bool netdev_offload_rebalance_policy = false;

bool
netdev_is_offload_rebalance_policy_enabled(void)
{
    return netdev_offload_rebalance_policy;
}

static void
netdev_ports_flow_init(void)
{
    struct port_to_netdev_data *data;

    ovs_rwlock_rdlock(&netdev_hmap_rwlock);
    HMAP_FOR_EACH (data, portno_node, &port_to_netdev) {
       netdev_init_flow_api(data->netdev);
    }
    ovs_rwlock_unlock(&netdev_hmap_rwlock);
}

//hw-offload初始化（仅初始化一次）
void
netdev_set_flow_api_enabled(const struct smap *ovs_other_config)
{
    if (smap_get_bool(ovs_other_config, "hw-offload", false)) {
        static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;

        if (ovsthread_once_start(&once)) {
            netdev_flow_api_enabled = true;

            offload_thread_nb = smap_get_ullong(ovs_other_config,
                                                "n-offload-threads",
                                                DEFAULT_OFFLOAD_THREAD_NB);
            if (offload_thread_nb > MAX_OFFLOAD_THREAD_NB) {
                VLOG_WARN("netdev: Invalid number of threads requested: %u",
                          offload_thread_nb);
                offload_thread_nb = DEFAULT_OFFLOAD_THREAD_NB;
            }

            if (smap_get(ovs_other_config, "n-offload-threads")) {
                VLOG_INFO("netdev: Flow API Enabled, using %u thread%s",
                          offload_thread_nb,
                          offload_thread_nb > 1 ? "s" : "");
            } else {
                VLOG_INFO("netdev: Flow API Enabled");
            }

#ifdef __linux__
            //设置flow rule的策略，是打到硬件，还是下到软件，还是都下
            tc_set_policy(smap_get_def(ovs_other_config, "tc-policy",
                                       TC_POLICY_DEFAULT));
#endif

            //是否开启offload-rebalance功能，帮助硬件解决cache不足问题
            if (smap_get_bool(ovs_other_config, "offload-rebalance", false)) {
                netdev_offload_rebalance_policy = true;
            }

            netdev_ports_flow_init();

            ovsthread_once_done(&once);
        }
    }
}
