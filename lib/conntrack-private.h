/*
 * Copyright (c) 2015, 2016 Nicira, Inc.
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

#ifndef CONNTRACK_PRIVATE_H
#define CONNTRACK_PRIVATE_H 1

#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip6.h>

#include "conntrack.h"
#include "ct-dpif.h"
#include "openvswitch/hmap.h"
#include "openvswitch/list.h"
#include "openvswitch/types.h"
#include "packets.h"
#include "unaligned.h"
#include "dp-packet.h"

struct ct_endpoint {
    struct ct_addr addr;
    union {
        ovs_be16 port;
        struct {
            ovs_be16 icmp_id;
            uint8_t icmp_type;
            uint8_t icmp_code;
        };
    };
};

/* Verify that there is no padding in struct ct_endpoint, to facilitate
 * hashing in ct_endpoint_hash_add(). */
BUILD_ASSERT_DECL(sizeof(struct ct_endpoint) == sizeof(struct ct_addr) + 4);

/* Changes to this structure need to be reflected in conn_key_hash() */
struct conn_key {
    struct ct_endpoint src;
    struct ct_endpoint dst;

    ovs_be16 dl_type;
    uint8_t nw_proto;
    uint16_t zone;
};

struct nat_conn_key_node {
    struct hmap_node node;
    struct conn_key key;
    struct conn_key value;
};

struct conn {
    struct conn_key key;//正向
    struct conn_key rev_key;//反向
    long long expiration;//过期时间
    struct ovs_list exp_node;//挂链用
    struct hmap_node node;//挂connect链
    ovs_u128 label;
    /* XXX: consider flattening. */
    struct nat_action_info_t *nat_info;//nat分配信息
    uint32_t mark;
    uint8_t conn_type;
};

enum ct_update_res {
    CT_UPDATE_INVALID,
    CT_UPDATE_VALID,
    CT_UPDATE_NEW,
};

enum ct_conn_type {
    CT_CONN_TYPE_DEFAULT,
    CT_CONN_TYPE_UN_NAT,//有nat资源的连接
};

struct ct_l4_proto {
    struct conn *(*new_conn)(struct conntrack_bucket *, struct dp_packet *pkt,
                             long long now);//新建连接
    bool (*valid_new)(struct dp_packet *pkt);//校验报文是否可以创建新连接
    enum ct_update_res (*conn_update)(struct conn *conn,
                                      struct conntrack_bucket *,
                                      struct dp_packet *pkt, bool reply,
                                      long long now);
    void (*conn_get_protoinfo)(const struct conn *,
                               struct ct_dpif_protoinfo *);
};

extern struct ct_l4_proto ct_proto_tcp;
extern struct ct_l4_proto ct_proto_other;
extern struct ct_l4_proto ct_proto_icmp4;
extern struct ct_l4_proto ct_proto_icmp6;

extern long long ct_timeout_val[];

//初始化过期链
static inline void
conn_init_expiration(struct conntrack_bucket *ctb, struct conn *conn,
                        enum ct_timeout tm, long long now)
{
	//加入对应的过期链
    conn->expiration = now + ct_timeout_val[tm];
    ovs_list_push_back(&ctb->exp_lists[tm], &conn->exp_node);
}

static inline void
conn_update_expiration(struct conntrack_bucket *ctb, struct conn *conn,
                       enum ct_timeout tm, long long now)
{
    ovs_list_remove(&conn->exp_node);
    conn_init_expiration(ctb, conn, tm, now);
}

//tcp payload 长度
static inline uint32_t
tcp_payload_length(struct dp_packet *pkt)
{
    const char *tcp_payload = dp_packet_get_tcp_payload(pkt);
    if (tcp_payload) {
        return ((char *) dp_packet_tail(pkt) - dp_packet_l2_pad_size(pkt)
                - tcp_payload);
    } else {
        return 0;
    }
}

#endif /* conntrack-private.h */
