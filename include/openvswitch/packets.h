/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013, 2014, 2015 Nicira, Inc.
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

#ifndef OPENVSWITCH_PACKETS_H
#define OPENVSWITCH_PACKETS_H 1

#include <sys/types.h>
#include <netinet/in.h>
#include "openvswitch/tun-metadata.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Tunnel information used in flow key and metadata. */
struct flow_tnl {
    ovs_be32 ip_dst;//填充隧道外层使用的目的ipv4地址／解隧道时，保存解出来的dst
    struct in6_addr ipv6_dst;//填充隧道外层使用的目的ipv6地址（与ip_dst仅一者可用）
    ovs_be32 ip_src;//解隧道时，保存解出来的src
    struct in6_addr ipv6_src;
    ovs_be64 tun_id;//解隧道时，填充解出来的tunnel-id
    uint16_t flags;//隧道标记位（1.是否容许分片标记；2.是否校验checksum;3.是否分析出tunnel-id）
    uint8_t ip_tos;//填充ip头部tos使用值／解隧道时，保存解出来的tos
    uint8_t ip_ttl;//填充ip头部ttl／解隧道时，保存解出来的ttl
    ovs_be16 tp_src;//解隧道时，填充解出来的src-port
    ovs_be16 tp_dst;//解隧道时，填充解出来的dst-port
    ovs_be16 gbp_id;
    uint8_t  gbp_flags;
    uint8_t erspan_ver;
    uint32_t erspan_idx;
    uint8_t erspan_dir;
    uint8_t erspan_hwid;
    uint8_t gtpu_flags;
    uint8_t gtpu_msgtype;
    uint8_t pad1[4];     /* Pad to 64 bits. */
    struct tun_metadata metadata;
};

/* Some flags are exposed through OpenFlow while others are used only
 * internally. */

/* Public flags */
#define FLOW_TNL_F_OAM (1 << 0)

#define FLOW_TNL_PUB_F_MASK ((1 << 1) - 1)

/* Private flags */
#define FLOW_TNL_F_DONT_FRAGMENT (1 << 1) /*标记不容许分片*/
#define FLOW_TNL_F_CSUM (1 << 2) //标记checksum已校验
#define FLOW_TNL_F_KEY (1 << 3) //（标记key已被填充）

#define FLOW_TNL_F_MASK ((1 << 4) - 1)

/* Unfortunately, a "struct flow" sometimes has to handle OpenFlow port
 * numbers and other times datapath (dpif) port numbers.  This union allows
 * access to both. */
union flow_in_port {
    odp_port_t odp_port;
    ofp_port_t ofp_port;
};

union flow_vlan_hdr {
    ovs_be32 qtag;
    struct {
    	//802.1Q标签的帧。TPID包含了一个固定的值0x8100 或者DOT1AD。
        ovs_be16 tpid;  /* ETH_TYPE_VLAN_DOT1Q or ETH_TYPE_DOT1AD */
        ovs_be16 tci;//Priority(3bit,0xe000) + Canonical Format Indicator( CFI ) (1 比特,0x1000） + VLAN Identified( VLAN ID ) (12比特）
    };
};

struct ovs_key_nsh {
    uint8_t flags;
    uint8_t ttl;
    uint8_t mdtype;
    uint8_t np;
    ovs_be32 path_hdr;
    ovs_be32 context[4];
};

/* NSH flags */
#define FLOW_NSH_F_OAM (1 << 0)
#define FLOW_NSH_F_CTX (1 << 1)

#define FLOW_NSH_F_MASK ((1 << 2) - 1)

#ifdef __cplusplus
}
#endif

#endif /* packets.h */
