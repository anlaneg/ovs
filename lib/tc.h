/*
 * Copyright (c) 2009, 2010, 2011, 2012, 2013, 2014, 2015, 2016, 2017 Nicira, Inc.
 * Copyright (c) 2016 Mellanox Technologies, Ltd.
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

#ifndef TC_H
#define TC_H 1

#include <sys/types.h>
#include <netinet/in.h> /* Must happen before linux/pkt_cls.h - Glibc #20215 */
#include <linux/pkt_cls.h>
#include <linux/pkt_sched.h>

#include "netlink-socket.h"
#include "odp-netlink.h"
#include "openvswitch/ofpbuf.h"
#include "openvswitch/flow.h"
#include "openvswitch/tun-metadata.h"

/* For backwards compatability with older kernels */
#ifndef TC_H_CLSACT
#define TC_H_CLSACT    TC_H_INGRESS
#endif
#ifndef TC_H_MIN_INGRESS
#define TC_H_MIN_INGRESS       0xFFF2U
#endif
#ifndef TC_H_MIN_EGRESS
#define TC_H_MIN_EGRESS       0xFFF3U
#endif

//ingress
#define TC_INGRESS_PARENT TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_INGRESS)
//egress
#define TC_EGRESS_PARENT TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_EGRESS)

#define TC_POLICY_DEFAULT "none"

enum tc_flower_reserved_prio {
    TC_RESERVED_PRIORITY_NONE,
    TC_RESERVED_PRIORITY_POLICE,
    __TC_RESERVED_PRIORITY_MAX
};
#define TC_RESERVED_PRIORITY_MAX (__TC_RESERVED_PRIORITY_MAX -1)

enum tc_qdisc_hook {
    TC_INGRESS,
    TC_EGRESS,
};

/* Returns tc handle 'major':'minor'. */
static inline unsigned int
tc_make_handle(unsigned int major, unsigned int minor)
{
    return TC_H_MAKE(major << 16, minor);
}

/* Returns the major number from 'handle'. */
static inline unsigned int
tc_get_major(unsigned int handle)
{
    return TC_H_MAJ(handle) >> 16;
}

/* Returns the minor number from 'handle'. */
static inline unsigned int
tc_get_minor(unsigned int handle)
{
    return TC_H_MIN(handle);
}

struct tcmsg *tc_make_request(int ifindex, int type,
                              unsigned int flags, struct ofpbuf *);
int tc_transact(struct ofpbuf *request, struct ofpbuf **replyp);
int tc_add_del_qdisc(int ifindex, bool add, uint32_t block_id,
                     enum tc_qdisc_hook hook);

struct tc_cookie {
    const void *data;
    size_t len;
};

struct tc_flower_key {
    ovs_be16 eth_type;//链路层报文格式
    uint8_t ip_proto;//ip协议号

    //二层填充信息
    struct eth_addr dst_mac;
    struct eth_addr src_mac;

    ovs_be32 mpls_lse;
    //tcp相关
    ovs_be16 tcp_src;
    ovs_be16 tcp_dst;
    ovs_be16 tcp_flags;//tcp flags支持

    //udp相关
    ovs_be16 udp_src;
    ovs_be16 udp_dst;

    //sctp相关
    ovs_be16 sctp_src;
    ovs_be16 sctp_dst;

    uint8_t icmp_code;
    uint8_t icmp_type;

    //0层vlan,1层vlan
    uint16_t vlan_id[FLOW_MAX_VLAN_HEADERS];
    uint8_t vlan_prio[FLOW_MAX_VLAN_HEADERS];

    //0层vlan,1层vlan分别对应的eth_type
    ovs_be16 encap_eth_type[FLOW_MAX_VLAN_HEADERS];

    uint8_t flags;
    uint8_t ip_ttl;
    uint8_t ip_tos;

    uint16_t ct_state;
    uint16_t ct_zone;
    uint32_t ct_mark;
    ovs_u128 ct_label;

    struct {
        ovs_be32 spa;
        ovs_be32 tpa;
        struct eth_addr sha;
        struct eth_addr tha;
        uint8_t opcode;
    } arp;

    struct {
        ovs_be32 ipv4_src;
        ovs_be32 ipv4_dst;
        uint8_t rewrite_ttl;
        uint8_t rewrite_tos;
    } ipv4;
    struct {
        struct in6_addr ipv6_src;
        struct in6_addr ipv6_dst;
        uint8_t rewrite_hlimit;
        uint8_t rewrite_tclass;
    } ipv6;

    struct {
        struct {
            ovs_be32 ipv4_src;
            ovs_be32 ipv4_dst;
        } ipv4;//tunnel的源ip,dstip
        struct {
            struct in6_addr ipv6_src;
            struct in6_addr ipv6_dst;
        } ipv6;
        uint8_t tos;//tunnel设置的tos
        uint8_t ttl;//tunnel设置的ttl
        ovs_be16 tp_src;//tunnel的传输层源端口号
        ovs_be16 tp_dst;//tunnel的传输层目的端口号
        ovs_be64 id;//tunnel id号（例如vxlan id)
        struct tun_metadata metadata;
    } tunnel;//隧道相关
};

enum tc_action_type {
    TC_ACT_OUTPUT,
    TC_ACT_ENCAP,//隧道封装
    TC_ACT_PEDIT,//报文修改
    TC_ACT_VLAN_POP,
    TC_ACT_VLAN_PUSH,
    TC_ACT_MPLS_POP,
    TC_ACT_MPLS_PUSH,
    TC_ACT_MPLS_SET,
    TC_ACT_GOTO,
    TC_ACT_CT,
};

enum nat_type {
    TC_NO_NAT = 0,
    TC_NAT_SRC,
    TC_NAT_DST,
    TC_NAT_RESTORE,
};

struct tc_action {
    union {
        int chain;

        struct {
            int ifindex_out;//出接口ifid
            bool ingress;//是否存放在ingress队列（仅internal类型接口在egress)
        } out;//output action

        struct {
            ovs_be16 vlan_push_tpid;//下一层eth_type
            uint16_t vlan_push_id;//vlan id号
            uint8_t vlan_push_prio;//vlan优先级
        } vlan;//vlan push action

        struct {
            ovs_be16 proto;
            uint32_t label;
            uint8_t tc;
            uint8_t ttl;
            uint8_t bos;
        } mpls;

        struct {
            bool id_present;//是否包含key
            ovs_be64 id;//tunnel id
            ovs_be16 tp_src;
            ovs_be16 tp_dst;//目的端口
            uint8_t tos;
            uint8_t ttl;
            uint8_t no_csum;
            struct {
                ovs_be32 ipv4_src;
                ovs_be32 ipv4_dst;
            } ipv4;
            struct {
                struct in6_addr ipv6_src;
                struct in6_addr ipv6_dst;
            } ipv6;
            struct tun_metadata data;
        } encap;//隧道封装action

        struct {
            uint16_t zone;
            uint32_t mark;
            uint32_t mark_mask;
            ovs_u128 label;
            ovs_u128 label_mask;
            uint8_t nat_type;
            struct {
                uint8_t ip_family;

                union {
                    struct {
                        ovs_be32 min;
                        ovs_be32 max;
                    } ipv4;
                    struct {
                        struct in6_addr min;
                        struct in6_addr max;
                    } ipv6;
                };

                struct {
                    ovs_be16 min;
                    ovs_be16 max;
                } port;

            } range;
            bool clear;
            bool force;
            bool commit;
        } ct;

        struct {
            struct tc_flower_key key;
            struct tc_flower_key mask;
        } rewrite;
     };

     enum tc_action_type type;//action类型
};

/* assert that if we overflow with a masked write of uint32_t to the last byte
 * of action.rewrite we overflow inside struct tc_action.
 * shouldn't happen unless someone moves rewrite to the end of action */
BUILD_ASSERT_DECL(offsetof(struct tc_action, rewrite)
                  + MEMBER_SIZEOF(struct tc_action, rewrite)
                  + sizeof(uint32_t) - 2 < sizeof(struct tc_action));

enum tc_offloaded_state {
    //offload状态未知
    TC_OFFLOADED_STATE_UNDEFINED,
    //offload 卸载在硬件
    TC_OFFLOADED_STATE_IN_HW,
    TC_OFFLOADED_STATE_NOT_IN_HW,
};

#define TCA_ACT_MAX_NUM 16

struct tcf_id {
    enum tc_qdisc_hook hook;
    uint32_t block_id;
    int ifindex;
    uint32_t chain;/*对应的chain*/
    uint16_t prio;
    uint32_t handle;/*tc规则对应的handle*/
};

/*构造tfilter的唯一链编号*/
static inline struct tcf_id
tc_make_tcf_id(int ifindex, uint32_t block_id, uint16_t prio,
               enum tc_qdisc_hook hook)
{
    struct tcf_id id = {
        .hook = hook,
        .block_id = block_id,
        .ifindex = ifindex,
        .prio = prio,
    };

    return id;
}

static inline struct tcf_id
tc_make_tcf_id_chain(int ifindex, uint32_t block_id, uint32_t chain,
                     uint16_t prio, enum tc_qdisc_hook hook)
{
    struct tcf_id id = tc_make_tcf_id(ifindex, block_id, prio, hook);

    id.chain = chain;

    return id;
}

static inline bool
is_tcf_id_eq(struct tcf_id *id1, struct tcf_id *id2)
{
    return id1->prio == id2->prio
           && id1->handle == id2->handle
           && id1->handle == id2->handle
           && id1->hook == id2->hook
           && id1->block_id == id2->block_id
           && id1->ifindex == id2->ifindex
           && id1->chain == id2->chain;
}

enum tc_offload_policy {
    TC_POLICY_NONE = 0,
    TC_POLICY_SKIP_SW,
    TC_POLICY_SKIP_HW
};

BUILD_ASSERT_DECL(TC_POLICY_NONE == 0);

struct tc_flower {
    struct tc_flower_key key;
    struct tc_flower_key mask;

    //记录由ovs转tc flower的actions
    int action_count;
    struct tc_action actions[TCA_ACT_MAX_NUM];

    /*flower统计信息，规则命中了多少报文及字节*/
    struct ovs_flow_stats stats_sw;
    struct ovs_flow_stats stats_hw;
    uint64_t lastused;

    uint32_t csum_update_flags;//标记需要执行checksum更新

    bool tunnel;//指明是否有tunnel区分

    struct tc_cookie act_cookie;//记录ufid

    bool needs_full_ip_proto_mask;

    enum tc_offloaded_state offloaded_state;
    /* Used to force skip_hw when probing tc features. */
    enum tc_offload_policy tc_policy;
};

int tc_replace_flower(struct tcf_id *id, struct tc_flower *flower);
int tc_del_filter(struct tcf_id *id);
int tc_get_flower(struct tcf_id *id, struct tc_flower *flower);
int tc_dump_flower_start(struct tcf_id *id, struct nl_dump *dump, bool terse);
int tc_dump_tc_chain_start(struct tcf_id *id, struct nl_dump *dump);
int parse_netlink_to_tc_flower(struct ofpbuf *reply,
                               struct tcf_id *id,
                               struct tc_flower *flower,
                               bool terse);
int parse_netlink_to_tc_chain(struct ofpbuf *reply, uint32_t *chain);
void tc_set_policy(const char *policy);

#endif /* tc.h */
