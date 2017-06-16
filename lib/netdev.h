/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013 Nicira, Inc.
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

#ifndef NETDEV_H
#define NETDEV_H 1

#include "openvswitch/netdev.h"
#include "openvswitch/types.h"
#include "packets.h"
#include "flow.h"

#ifdef  __cplusplus
extern "C" {
#endif

/* Generic interface to network devices ("netdev"s).
 *
 * Every port on a switch must have a corresponding netdev that must minimally
 * support a few operations, such as the ability to read the netdev's MTU.
 * The Porting section of the documentation has more information in the
 * "Writing a netdev Provider" section.
 *
 * Thread-safety
 * =============
 *
 * Most of the netdev functions are fully thread-safe: they may be called from
 * any number of threads on the same or different netdev objects.  The
 * exceptions are:
 *
 *    netdev_rxq_recv()
 *    netdev_rxq_wait()
 *    netdev_rxq_drain()
 *
 *      These functions are conditionally thread-safe: they may be called from
 *      different threads only on different netdev_rxq objects.  (The client may
 *      create multiple netdev_rxq objects for a single netdev and access each
 *      of those from a different thread.)
 *
 *    NETDEV_QUEUE_FOR_EACH
 *    netdev_queue_dump_next()
 *    netdev_queue_dump_done()
 *
 *      These functions are conditionally thread-safe: they may be called from
 *      different threads only on different netdev_queue_dump objects.  (The
 *      client may create multiple netdev_queue_dump objects for a single
 *      netdev and access each of those from a different thread.)
 */

struct dp_packet_batch;
struct dp_packet;
struct netdev_class;
struct netdev_rxq;
struct netdev_saved_flags;
struct ofpbuf;
struct in_addr;
struct in6_addr;
struct smap;
struct sset;
struct ovs_action_push_tnl;

/* Configuration specific to tunnels. */
struct netdev_tunnel_config {//tunnel配置结构体
    bool in_key_present;//in_key是否有效(是否配置了in_key或key)
    bool in_key_flow;//是否用流中的key(in)
    ovs_be64 in_key;

    bool out_key_present;//out_key是否有效
    bool out_key_flow;//是否用流中的key(out)
    ovs_be64 out_key;//tunnel id

    ovs_be16 dst_port;//tunnel的目的端口

    bool ip_src_flow;//是否用流中的src地址
    bool ip_dst_flow;//是否用流中的ip目的地址
    struct in6_addr ipv6_src;
    struct in6_addr ipv6_dst;//设置的ipv6目的地址（ipv4地址也在其中）

    uint32_t exts;
    bool set_egress_pkt_mark;
    uint32_t egress_pkt_mark;

    uint8_t ttl;//ttl设置值
    bool ttl_inherit;//是否使用原流中的ttl，如果为Fasle,则采用"ttl设置值“

    uint8_t tos;//tos设置值
    bool tos_inherit;//是否使用匹配流中的tos,如果为False,则采用"tos设置值“

    bool csum;//是否需要计算checksum
    bool dont_fragment;//是否要打上不容许分片标记
    bool is_layer3;
};

void netdev_run(void);
void netdev_wait(void);

void netdev_enumerate_types(struct sset *types);
bool netdev_is_reserved_name(const char *name);

int netdev_n_txq(const struct netdev *netdev);
int netdev_n_rxq(const struct netdev *netdev);
bool netdev_is_pmd(const struct netdev *netdev);
bool netdev_has_tunnel_push_pop(const struct netdev *netdev);

/* Open and close. */
int netdev_open(const char *name, const char *type, struct netdev **netdevp);

struct netdev *netdev_ref(const struct netdev *);
void netdev_remove(struct netdev *);
void netdev_close(struct netdev *);

void netdev_parse_name(const char *netdev_name, char **name, char **type);

/* Options. */
int netdev_set_config(struct netdev *, const struct smap *args, char **errp);
int netdev_get_config(const struct netdev *, struct smap *);
const struct netdev_tunnel_config *
    netdev_get_tunnel_config(const struct netdev *);
int netdev_get_numa_id(const struct netdev *);

/* Basic properties. */
const char *netdev_get_name(const struct netdev *);
const char *netdev_get_type(const struct netdev *);
const char *netdev_get_type_from_name(const char *);
int netdev_get_mtu(const struct netdev *, int *mtup);
int netdev_set_mtu(struct netdev *, int mtu);
void netdev_mtu_user_config(struct netdev *, bool);
bool netdev_mtu_is_user_config(struct netdev *);
int netdev_get_ifindex(const struct netdev *);
int netdev_set_tx_multiq(struct netdev *, unsigned int n_txq);

/* Packet reception. */
int netdev_rxq_open(struct netdev *, struct netdev_rxq **, int id);
void netdev_rxq_close(struct netdev_rxq *);

const char *netdev_rxq_get_name(const struct netdev_rxq *);
int netdev_rxq_get_queue_id(const struct netdev_rxq *);

int netdev_rxq_recv(struct netdev_rxq *rx, struct dp_packet_batch *);
void netdev_rxq_wait(struct netdev_rxq *);
int netdev_rxq_drain(struct netdev_rxq *);

/* Packet transmission. */
int netdev_send(struct netdev *, int qid, struct dp_packet_batch *,
                bool may_steal, bool concurrent_txq);
void netdev_send_wait(struct netdev *, int qid);

/* Flow offloading. */
struct offload_info {
    const void *port_hmap_obj; /* To query ports info from netdev port map */
    ovs_be16 tp_dst_port; /* Destination port for tunnel in SET action */
};
struct netdev_flow_dump;
int netdev_flow_flush(struct netdev *);
int netdev_flow_dump_create(struct netdev *, struct netdev_flow_dump **dump);
int netdev_flow_dump_destroy(struct netdev_flow_dump *);
bool netdev_flow_dump_next(struct netdev_flow_dump *, struct match *,
                          struct nlattr **actions, struct dpif_flow_stats *,
                          ovs_u128 *ufid, struct ofpbuf *rbuffer,
                          struct ofpbuf *wbuffer);
int netdev_flow_put(struct netdev *, struct match *, struct nlattr *actions,
                    size_t actions_len, const ovs_u128 *,
                    struct offload_info *, struct dpif_flow_stats *);
int netdev_flow_get(struct netdev *, struct match *, struct nlattr **actions,
                    const ovs_u128 *, struct dpif_flow_stats *,
                    struct ofpbuf *wbuffer);
int netdev_flow_del(struct netdev *, const ovs_u128 *,
                    struct dpif_flow_stats *);
int netdev_init_flow_api(struct netdev *);
bool netdev_is_flow_api_enabled(void);
void netdev_set_flow_api_enabled(const struct smap *ovs_other_config);

struct dpif_port;
int netdev_ports_insert(struct netdev *, const void *obj, struct dpif_port *);
struct netdev *netdev_ports_get(odp_port_t port, const void *obj);
int netdev_ports_remove(odp_port_t port, const void *obj);
odp_port_t netdev_ifindex_to_odp_port(int ifindex);
struct netdev_flow_dump **netdev_ports_flow_dump_create(const void *obj,
                                                        int *ports);
void netdev_ports_flow_flush(const void *obj);
int netdev_ports_flow_del(const void *obj, const ovs_u128 *ufid,
                          struct dpif_flow_stats *stats);
int netdev_ports_flow_get(const void *obj, struct match *match,
                          struct nlattr **actions,
                          const ovs_u128 *ufid,
                          struct dpif_flow_stats *stats,
                          struct ofpbuf *buf);

/* native tunnel APIs */
/* Structure to pass parameters required to build a tunnel header. */
struct netdev_tnl_build_header_params {
    const struct flow *flow;//tunnel对应的流解析出来的信息
    const struct in6_addr *s_ip;//填充时隧道外层使用的源ip地址
    struct eth_addr dmac;//填充时以太网目的mac
    struct eth_addr smac;//填充时以太网源mac
    bool is_ipv6;//是否使用ipv6协议(填充以太网头部时使用）
};

void
netdev_init_tnl_build_header_params(struct netdev_tnl_build_header_params *params,
                                    const struct flow *tnl_flow,
                                    const struct in6_addr *src,
                                    struct eth_addr dmac,
                                    struct eth_addr smac);

int netdev_build_header(const struct netdev *, struct ovs_action_push_tnl *data,
                        const struct netdev_tnl_build_header_params *params);

int netdev_push_header(const struct netdev *netdev,
                       struct dp_packet_batch *,
                       const struct ovs_action_push_tnl *data);
void netdev_pop_header(struct netdev *netdev, struct dp_packet_batch *);

/* Hardware address. */
int netdev_set_etheraddr(struct netdev *, const struct eth_addr mac);
int netdev_get_etheraddr(const struct netdev *, struct eth_addr *mac);

/* PHY interface. */
bool netdev_get_carrier(const struct netdev *);
long long int netdev_get_carrier_resets(const struct netdev *);
int netdev_set_miimon_interval(struct netdev *, long long int interval);

/* Flags. */
enum netdev_flags {
    NETDEV_UP = 0x0001,         /* Device enabled? */
    NETDEV_PROMISC = 0x0002,    /* Promiscuous mode? */
    NETDEV_LOOPBACK = 0x0004    /* This is a loopback device. */
};

int netdev_get_flags(const struct netdev *, enum netdev_flags *);
int netdev_set_flags(struct netdev *, enum netdev_flags,
                     struct netdev_saved_flags **);
int netdev_turn_flags_on(struct netdev *, enum netdev_flags,
                         struct netdev_saved_flags **);
int netdev_turn_flags_off(struct netdev *, enum netdev_flags,
                          struct netdev_saved_flags **);

void netdev_restore_flags(struct netdev_saved_flags *);

/* TCP/IP stack interface. */
int netdev_set_in4(struct netdev *, struct in_addr addr, struct in_addr mask);
int netdev_get_in4_by_name(const char *device_name, struct in_addr *in4);
int netdev_get_addr_list(const struct netdev *netdev, struct in6_addr **addr,
                         struct in6_addr **mask, int *n_in6);

int netdev_add_router(struct netdev *, struct in_addr router);
int netdev_get_next_hop(const struct netdev *, const struct in_addr *host,
                        struct in_addr *next_hop, char **);
int netdev_get_status(const struct netdev *, struct smap *);
int netdev_arp_lookup(const struct netdev *, ovs_be32 ip,
                      struct eth_addr *mac);

struct netdev *netdev_find_dev_by_in4(const struct in_addr *);

/* Statistics. */
int netdev_get_stats(const struct netdev *, struct netdev_stats *);

/* Quality of service. */
struct netdev_qos_capabilities {
    unsigned int n_queues;
};

struct netdev_queue_stats {
    /* Values of unsupported statistics are set to all-1-bits (UINT64_MAX). */
    uint64_t tx_bytes;
    uint64_t tx_packets;
    uint64_t tx_errors;

    /* Time at which the queue was created, in msecs, LLONG_MIN if unknown. */
    long long int created;
};

int netdev_set_policing(struct netdev *, uint32_t kbits_rate,
                        uint32_t kbits_burst);

int netdev_get_qos_types(const struct netdev *, struct sset *types);
int netdev_get_qos_capabilities(const struct netdev *,
                                const char *type,
                                struct netdev_qos_capabilities *);
int netdev_get_n_queues(const struct netdev *,
                        const char *type, unsigned int *n_queuesp);

int netdev_get_qos(const struct netdev *,
                   const char **typep, struct smap *details);
int netdev_set_qos(struct netdev *,
                   const char *type, const struct smap *details);

int netdev_get_queue(const struct netdev *,
                     unsigned int queue_id, struct smap *details);
int netdev_set_queue(struct netdev *,
                     unsigned int queue_id, const struct smap *details);
int netdev_delete_queue(struct netdev *, unsigned int queue_id);
int netdev_get_queue_stats(const struct netdev *, unsigned int queue_id,
                           struct netdev_queue_stats *);
uint64_t netdev_get_change_seq(const struct netdev *);

int netdev_reconfigure(struct netdev *netdev);
void netdev_wait_reconf_required(struct netdev *netdev);
bool netdev_is_reconf_required(struct netdev *netdev);

struct netdev_queue_dump {
    struct netdev *netdev;
    int error;
    void *state;
};
void netdev_queue_dump_start(struct netdev_queue_dump *,
                             const struct netdev *);
bool netdev_queue_dump_next(struct netdev_queue_dump *,
                            unsigned int *queue_id, struct smap *details);
int netdev_queue_dump_done(struct netdev_queue_dump *);

/* Iterates through each queue in NETDEV, using DUMP as state.  Fills QUEUE_ID
 * and DETAILS with information about queues.  The client must initialize and
 * destroy DETAILS.
 *
 * Arguments all have pointer type.
 *
 * If you break out of the loop, then you need to free the dump structure by
 * hand using netdev_queue_dump_done(). */
#define NETDEV_QUEUE_FOR_EACH(QUEUE_ID, DETAILS, DUMP, NETDEV)  \
    for (netdev_queue_dump_start(DUMP, NETDEV);                 \
         (netdev_queue_dump_next(DUMP, QUEUE_ID, DETAILS)       \
          ? true                                                \
          : (netdev_queue_dump_done(DUMP), false));             \
        )

typedef void netdev_dump_queue_stats_cb(unsigned int queue_id,
                                        struct netdev_queue_stats *,
                                        void *aux);
int netdev_dump_queue_stats(const struct netdev *,
                            netdev_dump_queue_stats_cb *, void *aux);

extern struct seq *tnl_conf_seq;

#ifndef _WIN32
void netdev_get_addrs_list_flush(void);
int netdev_get_addrs(const char dev[], struct in6_addr **paddr,
                     struct in6_addr **pmask, int *n_in6);
#endif

#ifdef  __cplusplus
}
#endif

#endif /* netdev.h */
