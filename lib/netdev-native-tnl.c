/*
 * Copyright (c) 2016 Nicira, Inc.
 * Copyright (c) 2016 Red Hat, Inc.
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

#include "netdev-native-tnl.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <sys/ioctl.h>

#include <errno.h>
#include <stdlib.h>
#include <sys/time.h>

#include "byte-order.h"
#include "csum.h"
#include "dp-packet.h"
#include "netdev.h"
#include "netdev-vport.h"
#include "netdev-vport-private.h"
#include "odp-netlink.h"
#include "packets.h"
#include "seq.h"
#include "unaligned.h"
#include "unixctl.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(native_tnl);
static struct vlog_rate_limit err_rl = VLOG_RATE_LIMIT_INIT(60, 5);

#define VXLAN_HLEN   (sizeof(struct udp_header) +         \
                      sizeof(struct vxlanhdr))

#define GENEVE_BASE_HLEN   (sizeof(struct udp_header) +         \
                            sizeof(struct genevehdr))

uint16_t tnl_udp_port_min = 32768;
uint16_t tnl_udp_port_max = 61000;

//从隧道中解出ip层信息，并将其填充进tnl中（src-ip,dst-ip,tos,ttl信息获取)
void *
netdev_tnl_ip_extract_tnl_md(struct dp_packet *packet, struct flow_tnl *tnl,
                  unsigned int *hlen)
{
    void *nh;
    struct ip_header *ip;
    struct ovs_16aligned_ip6_hdr *ip6;
    void *l4;
    int l3_size;

    nh = dp_packet_l3(packet);
    ip = nh;
    ip6 = nh;
    l4 = dp_packet_l4(packet);

    if (!nh || !l4) {
        return NULL;
    }

    *hlen = sizeof(struct eth_header);

    //含l3 header后报文的数据总长度
    l3_size = dp_packet_size(packet) -
              ((char *)nh - (char *)dp_packet_data(packet));

    if (IP_VER(ip->ip_ihl_ver) == 4) {//是ipv4报文

        ovs_be32 ip_src, ip_dst;

        if (OVS_UNLIKELY(!dp_packet_ip_checksum_valid(packet))) {
            if (csum(ip, IP_IHL(ip->ip_ihl_ver) * 4)) {//校验iphdr头
                VLOG_WARN_RL(&err_rl, "ip packet has invalid checksum");
                return NULL;
            }
        }

        if (ntohs(ip->ip_tot_len) > l3_size) {//ip头部信息不正确
            VLOG_WARN_RL(&err_rl, "ip packet is truncated (IP length %d, actual %d)",
                         ntohs(ip->ip_tot_len), l3_size);
            return NULL;
        }
        if (IP_IHL(ip->ip_ihl_ver) * 4 > sizeof(struct ip_header)) {//tunnel不支持ipv4选项，为什么？
            VLOG_WARN_RL(&err_rl, "ip options not supported on tunnel packets "
                         "(%d bytes)", IP_IHL(ip->ip_ihl_ver) * 4);
            return NULL;
        }

        ip_src = get_16aligned_be32(&ip->ip_src);
        ip_dst = get_16aligned_be32(&ip->ip_dst);

        tnl->ip_src = ip_src;
        tnl->ip_dst = ip_dst;
        tnl->ip_tos = ip->ip_tos;
        tnl->ip_ttl = ip->ip_ttl;

        *hlen += IP_HEADER_LEN;

    } else if (IP_VER(ip->ip_ihl_ver) == 6) {//ipv6报文
        ovs_be32 tc_flow = get_16aligned_be32(&ip6->ip6_flow);

        memcpy(tnl->ipv6_src.s6_addr, ip6->ip6_src.be16, sizeof ip6->ip6_src);
        memcpy(tnl->ipv6_dst.s6_addr, ip6->ip6_dst.be16, sizeof ip6->ip6_dst);

        tnl->ip_tos = ntohl(tc_flow) >> 20;
        tnl->ip_ttl = ip6->ip6_hlim;

        *hlen += IPV6_HEADER_LEN;

    } else {//其它类型报文
        VLOG_WARN_RL(&err_rl, "ipv4 packet has invalid version (%d)",
                     IP_VER(ip->ip_ihl_ver));
        return NULL;
    }

    return l4;
}

/* Pushes the 'size' bytes of 'header' into the headroom of 'packet',
 * reallocating the packet if necessary.  'header' should contain an Ethernet
 * header, followed by an IPv4 header (without options), and an L4 header.
 *
 * This function sets the IP header's ip_tot_len field (which should be zeroed
 * as part of 'header') and puts its value into '*ip_tot_size' as well.  Also
 * updates IP header checksum.
 *
 * Return pointer to the L4 header added to 'packet'. */
void *
netdev_tnl_push_ip_header(struct dp_packet *packet,
               const void *header, int size, int *ip_tot_size)//返回的ip_tot_size是不计算ipv4头长度的
{
    struct eth_header *eth;
    struct ip_header *ip;
    struct ovs_16aligned_ip6_hdr *ip6;

    eth = dp_packet_push_uninit(packet, size);
    *ip_tot_size = dp_packet_size(packet) - sizeof (struct eth_header);//计算ip totoal size

    memcpy(eth, header, size);//将header放入

    if (netdev_tnl_is_header_ipv6(header)) {//放入的header是否为ipv6协议
        ip6 = netdev_tnl_ipv6_hdr(eth);
        *ip_tot_size -= IPV6_HEADER_LEN;//ipv6需要支除头长度
        ip6->ip6_plen = htons(*ip_tot_size);
        return ip6 + 1;
    } else {
        ip = netdev_tnl_ip_hdr(eth);
        ip->ip_tot_len = htons(*ip_tot_size);//填充ip total length
        ip->ip_csum = recalc_csum16(ip->ip_csum, 0, ip->ip_tot_len);//计算check sum
        *ip_tot_size -= IP_HEADER_LEN;
        return ip + 1;
    }
}

//udp隧道信息解出来metadata
static void *
udp_extract_tnl_md(struct dp_packet *packet, struct flow_tnl *tnl,
                   unsigned int *hlen)
{
    struct udp_header *udp;

    udp = netdev_tnl_ip_extract_tnl_md(packet, tnl, hlen);
    if (!udp) {
        return NULL;
    }

    if (udp->udp_csum) {
        if (OVS_UNLIKELY(!dp_packet_l4_checksum_valid(packet))) {
            uint32_t csum;
            if (netdev_tnl_is_header_ipv6(dp_packet_data(packet))) {
                csum = packet_csum_pseudoheader6(dp_packet_l3(packet));
            } else {
                csum = packet_csum_pseudoheader(dp_packet_l3(packet));
            }

            csum = csum_continue(csum, udp, dp_packet_size(packet) -
                                 ((const unsigned char *)udp -
                                  (const unsigned char *)dp_packet_l2(packet)
                                 ));
            if (csum_finish(csum)) {
                return NULL;
            }
        }
        tnl->flags |= FLOW_TNL_F_CSUM;
    }

    tnl->tp_src = udp->udp_src;
    tnl->tp_dst = udp->udp_dst;

    return udp + 1;
}


//给定报文，为这些报文封闭vxlan头
//由于data数据类型中已填充好了必要的模板头，故（1）将模板直接copy进mbuf（2）填充ipv total length
//(3) 计算ipv4 checksum (4)随机填充一个src port (5)填充udp总长度 (6)计算udp checksum
void
netdev_tnl_push_udp_header(struct dp_packet *packet,
                           const struct ovs_action_push_tnl *data)
{
    struct udp_header *udp;
    int ip_tot_size;

    udp = netdev_tnl_push_ip_header(packet, data->header, data->header_len, &ip_tot_size);

    /* set udp src port */
    udp->udp_src = netdev_tnl_get_src_port(packet);
    udp->udp_len = htons(ip_tot_size);//填充udp长度（不含ipv4头）

    if (udp->udp_csum) {//计算udp的checksum
        uint32_t csum;
        if (netdev_tnl_is_header_ipv6(dp_packet_data(packet))) {
            csum = packet_csum_pseudoheader6(netdev_tnl_ipv6_hdr(dp_packet_data(packet)));
        } else {
            csum = packet_csum_pseudoheader(netdev_tnl_ip_hdr(dp_packet_data(packet)));
        }

        csum = csum_continue(csum, udp, ip_tot_size);
        udp->udp_csum = csum_finish(csum);

        if (!udp->udp_csum) {
            udp->udp_csum = htons(0xffff);
        }
    }
}

//构造以太头（填充dmac,smac,协议
static void *
eth_build_header(struct ovs_action_push_tnl *data,
                 const struct netdev_tnl_build_header_params *params)
{
    uint16_t eth_proto = params->is_ipv6 ? ETH_TYPE_IPV6 : ETH_TYPE_IP;
    struct eth_header *eth;

    memset(data->header, 0, sizeof data->header);

    eth = (struct eth_header *)data->header;
    eth->eth_dst = params->dmac;
    eth->eth_src = params->smac;
    eth->eth_type = htons(eth_proto);
    data->header_len = sizeof(struct eth_header);
    return eth + 1;
}

//构造隧道ip，以太网头
void *
netdev_tnl_ip_build_header(struct ovs_action_push_tnl *data,
                           const struct netdev_tnl_build_header_params *params,
                           uint8_t next_proto)
{
    void *l3;

    l3 = eth_build_header(data, params);
    if (!params->is_ipv6) {//构造ipv4头
        ovs_be32 ip_src = in6_addr_get_mapped_ipv4(params->s_ip);
        struct ip_header *ip;

        ip = (struct ip_header *) l3;

        ip->ip_ihl_ver = IP_IHL_VER(5, 4);//写死的ipv4头长度（不含扩展）
        ip->ip_tos = params->flow->tunnel.ip_tos;
        ip->ip_ttl = params->flow->tunnel.ip_ttl;
        ip->ip_proto = next_proto;//预填充上层协议
        put_16aligned_be32(&ip->ip_src, ip_src);
        put_16aligned_be32(&ip->ip_dst, params->flow->tunnel.ip_dst);

        ip->ip_frag_off = (params->flow->tunnel.flags & FLOW_TNL_F_DONT_FRAGMENT) ?
                          htons(IP_DF) : 0;

        /* Checksum has already been zeroed by eth_build_header. */
        ip->ip_csum = csum(ip, sizeof *ip);//填充ip头部checksum

        data->header_len += IP_HEADER_LEN;
        return ip + 1;
    } else {//ipv6头部填充
        struct ovs_16aligned_ip6_hdr *ip6;

        ip6 = (struct ovs_16aligned_ip6_hdr *) l3;

        put_16aligned_be32(&ip6->ip6_flow, htonl(6 << 28) |
                           htonl(params->flow->tunnel.ip_tos << 20));
        ip6->ip6_hlim = params->flow->tunnel.ip_ttl;
        ip6->ip6_nxt = next_proto;
        memcpy(&ip6->ip6_src, params->s_ip, sizeof(ovs_be32[4]));
        memcpy(&ip6->ip6_dst, &params->flow->tunnel.ipv6_dst, sizeof(ovs_be32[4]));

        data->header_len += IPV6_HEADER_LEN;
        return ip6 + 1;
    }
}

//构造udp头，ip头，ethhdr头（udp头的src-port未填充）
static void *
udp_build_header(struct netdev_tunnel_config *tnl_cfg,
                 struct ovs_action_push_tnl *data,
                 const struct netdev_tnl_build_header_params *params)
{
    struct udp_header *udp;

    udp = netdev_tnl_ip_build_header(data, params, IPPROTO_UDP);
    udp->udp_dst = tnl_cfg->dst_port;

    if (params->is_ipv6 || params->flow->tunnel.flags & FLOW_TNL_F_CSUM) {
        /* Write a value in now to mark that we should compute the checksum
         * later. 0xffff is handy because it is transparent to the
         * calculation. */
        udp->udp_csum = htons(0xffff);
    }
    data->header_len += sizeof *udp;
    return udp + 1;
}

static int
gre_header_len(ovs_be16 flags)
{
    int hlen = 4;

    if (flags & htons(GRE_CSUM)) {
        hlen += 4;
    }
    if (flags & htons(GRE_KEY)) {
        hlen += 4;
    }
    if (flags & htons(GRE_SEQ)) {
        hlen += 4;
    }
    return hlen;
}

static int
parse_gre_header(struct dp_packet *packet,
                 struct flow_tnl *tnl)
{
    const struct gre_base_hdr *greh;
    ovs_16aligned_be32 *options;
    int hlen;
    unsigned int ulen;

    greh = netdev_tnl_ip_extract_tnl_md(packet, tnl, &ulen);
    if (!greh) {
        return -EINVAL;
    }

    if (greh->flags & ~(htons(GRE_CSUM | GRE_KEY | GRE_SEQ))) {
        return -EINVAL;
    }

    if (greh->protocol != htons(ETH_TYPE_TEB)) {
        return -EINVAL;
    }

    hlen = ulen + gre_header_len(greh->flags);
    if (hlen > dp_packet_size(packet)) {
        return -EINVAL;
    }

    options = (ovs_16aligned_be32 *)(greh + 1);
    if (greh->flags & htons(GRE_CSUM)) {
        ovs_be16 pkt_csum;

        pkt_csum = csum(greh, dp_packet_size(packet) -
                              ((const unsigned char *)greh -
                               (const unsigned char *)dp_packet_l2(packet)));
        if (pkt_csum) {
            return -EINVAL;
        }
        tnl->flags = FLOW_TNL_F_CSUM;
        options++;
    }

    if (greh->flags & htons(GRE_KEY)) {
        tnl->tun_id = be32_to_be64(get_16aligned_be32(options));
        tnl->flags |= FLOW_TNL_F_KEY;
        options++;
    }

    if (greh->flags & htons(GRE_SEQ)) {
        options++;
    }

    return hlen;
}

struct dp_packet *
netdev_gre_pop_header(struct dp_packet *packet)
{
    struct pkt_metadata *md = &packet->md;
    struct flow_tnl *tnl = &md->tunnel;
    int hlen = sizeof(struct eth_header) + 4;

    hlen += netdev_tnl_is_header_ipv6(dp_packet_data(packet)) ?
            IPV6_HEADER_LEN : IP_HEADER_LEN;

    pkt_metadata_init_tnl(md);
    if (hlen > dp_packet_size(packet)) {
        goto err;
    }

    hlen = parse_gre_header(packet, tnl);
    if (hlen < 0) {
        goto err;
    }

    dp_packet_reset_packet(packet, hlen);

    return packet;
err:
    dp_packet_delete(packet);
    return NULL;
}

void
netdev_gre_push_header(struct dp_packet *packet,
                       const struct ovs_action_push_tnl *data)
{
    struct gre_base_hdr *greh;
    int ip_tot_size;

    greh = netdev_tnl_push_ip_header(packet, data->header, data->header_len, &ip_tot_size);

    if (greh->flags & htons(GRE_CSUM)) {
        ovs_be16 *csum_opt = (ovs_be16 *) (greh + 1);
        *csum_opt = csum(greh, ip_tot_size);
    }
}

int
netdev_gre_build_header(const struct netdev *netdev,
                        struct ovs_action_push_tnl *data,
                        const struct netdev_tnl_build_header_params *params)
{
    struct netdev_vport *dev = netdev_vport_cast(netdev);
    struct netdev_tunnel_config *tnl_cfg;
    struct gre_base_hdr *greh;
    ovs_16aligned_be32 *options;
    unsigned int hlen;

    /* XXX: RCUfy tnl_cfg. */
    ovs_mutex_lock(&dev->mutex);
    tnl_cfg = &dev->tnl_cfg;

    greh = netdev_tnl_ip_build_header(data, params, IPPROTO_GRE);

    greh->protocol = htons(ETH_TYPE_TEB);
    greh->flags = 0;

    options = (ovs_16aligned_be32 *) (greh + 1);
    if (params->flow->tunnel.flags & FLOW_TNL_F_CSUM) {
        greh->flags |= htons(GRE_CSUM);
        put_16aligned_be32(options, 0);
        options++;
    }

    if (tnl_cfg->out_key_present) {
        greh->flags |= htons(GRE_KEY);
        put_16aligned_be32(options, be64_to_be32(params->flow->tunnel.tun_id));
        options++;
    }

    ovs_mutex_unlock(&dev->mutex);

    hlen = (uint8_t *) options - (uint8_t *) greh;

    data->header_len += hlen;
    data->tnl_type = OVS_VPORT_TYPE_GRE;
    return 0;
}

//vxlan隧道头剥离（填充必要的md字段）
struct dp_packet *
netdev_vxlan_pop_header(struct dp_packet *packet)
{
    struct pkt_metadata *md = &packet->md;
    struct flow_tnl *tnl = &md->tunnel;
    struct vxlanhdr *vxh;
    unsigned int hlen;

    pkt_metadata_init_tnl(md);
    if (VXLAN_HLEN > dp_packet_l4_size(packet)) {//报文长度要大于udphdr+vxlanhdr
        goto err;
    }

    vxh = udp_extract_tnl_md(packet, tnl, &hlen);//解udp
    if (!vxh) {
        goto err;
    }

    if (get_16aligned_be32(&vxh->vx_flags) != htonl(VXLAN_FLAGS) ||
       (get_16aligned_be32(&vxh->vx_vni) & htonl(0xff))) {//检查flag及预留字段
        VLOG_WARN_RL(&err_rl, "invalid vxlan flags=%#x vni=%#x\n",
                     ntohl(get_16aligned_be32(&vxh->vx_flags)),
                     ntohl(get_16aligned_be32(&vxh->vx_vni)));
        goto err;
    }
    tnl->tun_id = htonll(ntohl(get_16aligned_be32(&vxh->vx_vni)) >> 8);
    tnl->flags |= FLOW_TNL_F_KEY;

    dp_packet_reset_packet(packet, hlen + VXLAN_HLEN);

    return packet;
err:
    dp_packet_delete(packet);
    return NULL;
}

//构造vxlan头
int
netdev_vxlan_build_header(const struct netdev *netdev,
                          struct ovs_action_push_tnl *data,
                          const struct netdev_tnl_build_header_params *params)
{
    struct netdev_vport *dev = netdev_vport_cast(netdev);
    struct netdev_tunnel_config *tnl_cfg;
    struct vxlanhdr *vxh;

    /* XXX: RCUfy tnl_cfg. */
    ovs_mutex_lock(&dev->mutex);
    tnl_cfg = &dev->tnl_cfg;

    vxh = udp_build_header(tnl_cfg, data, params);

    //填充vxlan头
    put_16aligned_be32(&vxh->vx_flags, htonl(VXLAN_FLAGS));
    put_16aligned_be32(&vxh->vx_vni, htonl(ntohll(params->flow->tunnel.tun_id) << 8));

    ovs_mutex_unlock(&dev->mutex);
    data->header_len += sizeof *vxh;
    data->tnl_type = OVS_VPORT_TYPE_VXLAN;
    return 0;
}

struct dp_packet *
netdev_geneve_pop_header(struct dp_packet *packet)
{
    struct pkt_metadata *md = &packet->md;
    struct flow_tnl *tnl = &md->tunnel;
    struct genevehdr *gnh;
    unsigned int hlen, opts_len, ulen;

    pkt_metadata_init_tnl(md);
    if (GENEVE_BASE_HLEN > dp_packet_l4_size(packet)) {
        VLOG_WARN_RL(&err_rl, "geneve packet too small: min header=%u packet size=%"PRIuSIZE"\n",
                     (unsigned int)GENEVE_BASE_HLEN, dp_packet_l4_size(packet));
        goto err;
    }

    gnh = udp_extract_tnl_md(packet, tnl, &ulen);
    if (!gnh) {
        goto err;
    }

    opts_len = gnh->opt_len * 4;
    hlen = ulen + GENEVE_BASE_HLEN + opts_len;
    if (hlen > dp_packet_size(packet)) {
        VLOG_WARN_RL(&err_rl, "geneve packet too small: header len=%u packet size=%u\n",
                     hlen, dp_packet_size(packet));
        goto err;
    }

    if (gnh->ver != 0) {
        VLOG_WARN_RL(&err_rl, "unknown geneve version: %"PRIu8"\n", gnh->ver);
        goto err;
    }

    if (gnh->proto_type != htons(ETH_TYPE_TEB)) {
        VLOG_WARN_RL(&err_rl, "unknown geneve encapsulated protocol: %#x\n",
                     ntohs(gnh->proto_type));
        goto err;
    }

    tnl->flags |= gnh->oam ? FLOW_TNL_F_OAM : 0;
    tnl->tun_id = htonll(ntohl(get_16aligned_be32(&gnh->vni)) >> 8);
    tnl->flags |= FLOW_TNL_F_KEY;

    memcpy(tnl->metadata.opts.gnv, gnh->options, opts_len);
    tnl->metadata.present.len = opts_len;
    tnl->flags |= FLOW_TNL_F_UDPIF;

    dp_packet_reset_packet(packet, hlen);

    return packet;
err:
    dp_packet_delete(packet);
    return NULL;
}

int
netdev_geneve_build_header(const struct netdev *netdev,
                           struct ovs_action_push_tnl *data,
                           const struct netdev_tnl_build_header_params *params)
{
    struct netdev_vport *dev = netdev_vport_cast(netdev);
    struct netdev_tunnel_config *tnl_cfg;
    struct genevehdr *gnh;
    int opt_len;
    bool crit_opt;

    /* XXX: RCUfy tnl_cfg. */
    ovs_mutex_lock(&dev->mutex);
    tnl_cfg = &dev->tnl_cfg;

    gnh = udp_build_header(tnl_cfg, data, params);

    put_16aligned_be32(&gnh->vni, htonl(ntohll(params->flow->tunnel.tun_id) << 8));

    ovs_mutex_unlock(&dev->mutex);

    opt_len = tun_metadata_to_geneve_header(&params->flow->tunnel,
                                            gnh->options, &crit_opt);

    gnh->opt_len = opt_len / 4;
    gnh->oam = !!(params->flow->tunnel.flags & FLOW_TNL_F_OAM);
    gnh->critical = crit_opt ? 1 : 0;
    gnh->proto_type = htons(ETH_TYPE_TEB);

    data->header_len += sizeof *gnh + opt_len;
    data->tnl_type = OVS_VPORT_TYPE_GENEVE;
    return 0;
}


void
netdev_tnl_egress_port_range(struct unixctl_conn *conn, int argc,
                             const char *argv[], void *aux OVS_UNUSED)
{
    int val1, val2;

    if (argc < 3) {
        struct ds ds = DS_EMPTY_INITIALIZER;

        ds_put_format(&ds, "Tunnel UDP source port range: %"PRIu16"-%"PRIu16"\n",
                            tnl_udp_port_min, tnl_udp_port_max);

        unixctl_command_reply(conn, ds_cstr(&ds));
        ds_destroy(&ds);
        return;
    }

    if (argc != 3) {
        return;
    }

    val1 = atoi(argv[1]);
    if (val1 <= 0 || val1 > UINT16_MAX) {
        unixctl_command_reply(conn, "Invalid min.");
        return;
    }
    val2 = atoi(argv[2]);
    if (val2 <= 0 || val2 > UINT16_MAX) {
        unixctl_command_reply(conn, "Invalid max.");
        return;
    }

    if (val1 > val2) {
        tnl_udp_port_min = val2;
        tnl_udp_port_max = val1;
    } else {
        tnl_udp_port_min = val1;
        tnl_udp_port_max = val2;
    }
    seq_change(tnl_conf_seq);

    unixctl_command_reply(conn, "OK");
}
