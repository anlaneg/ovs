/*-
 * Copyright (c) 2001 Daniel Hartmeier
 * Copyright (c) 2002 - 2008 Henning Brauer
 * Copyright (c) 2012 Gleb Smirnoff <glebius@FreeBSD.org>
 * Copyright (c) 2015, 2016 Nicira, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *    - Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    - Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials provided
 *      with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Effort sponsored in part by the Defense Advanced Research Projects
 * Agency (DARPA) and Air Force Research Laboratory, Air Force
 * Materiel Command, USAF, under agreement number F30602-01-2-0537.
 *
 *      $OpenBSD: pf.c,v 1.634 2009/02/27 12:37:45 henning Exp $
 */

#include <config.h>

#include "conntrack-private.h"
#include "conntrack-tp.h"
#include "coverage.h"
#include "ct-dpif.h"
#include "dp-packet.h"
#include "util.h"

COVERAGE_DEFINE(conntrack_tcp_seq_chk_bypass);
COVERAGE_DEFINE(conntrack_tcp_seq_chk_failed);
COVERAGE_DEFINE(conntrack_invalid_tcp_flags);

struct tcp_peer {
    uint32_t               seqlo;          /* Max sequence number sent     */ //本端发送的seq
    uint32_t               seqhi;          /* Max the other end ACKd + win */ //对端需要ack的seq
    uint16_t               max_win;        /* largest window (pre scaling) */ //最大窗口大小
    uint8_t                wscale;         /* window scaling factor        */ //窗口放大因子
    enum ct_dpif_tcp_state state;//tcp状态
};

//tcp链连跟踪
struct conn_tcp {
    struct conn up;//基类
    struct tcp_peer peer[2]; /* 'conn' lock protected. *///src，目地
};

enum {
    TCPOPT_EOL,
    TCPOPT_NOP,
    TCPOPT_WINDOW = 3,
};

/* TCP sequence numbers are 32 bit integers operated
 * on with modular arithmetic.  These macros can be
 * used to compare such integers. */
#define SEQ_LT(a,b)     INT_MOD_LT(a, b)
#define SEQ_LEQ(a,b)    INT_MOD_LEQ(a, b)
#define SEQ_GT(a,b)     INT_MOD_GT(a, b)
#define SEQ_GEQ(a,b)    INT_MOD_GEQ(a, b)

#define SEQ_MIN(a, b)   INT_MOD_MIN(a, b)
#define SEQ_MAX(a, b)   INT_MOD_MAX(a, b)

static struct conn_tcp*
conn_tcp_cast(const struct conn* conn)
{
    return CONTAINER_OF(conn, struct conn_tcp, up);
}

/* pf does this in in pf_normalize_tcp(), and it is called only if scrub
 * is enabled.  We're not scrubbing, but this check seems reasonable.  */
//检查tcp标记位是否无效
static bool
tcp_invalid_flags(uint16_t flags)
{

	//有syn标记时，不得有rst或fin标记
    if (flags & TCP_SYN) {
        if (flags & TCP_RST || flags & TCP_FIN) {
            return true;
        }
    } else {
        /* Illegal packet */
    		//没有syn标记时，竞然没有ack或者rst标记，有误的报文
        if (!(flags & (TCP_ACK|TCP_RST))) {
            return true;
        }
    }

    if (!(flags & TCP_ACK)) {
        /* These flags are only valid if ACK is set */
    		//ack标记不存在时，有fin,push,urg标记设置则有误
        if ((flags & TCP_FIN) || (flags & TCP_PSH) || (flags & TCP_URG)) {
            return true;
        }
    }

    //标记位有效
    return false;
}

#define TCP_MAX_WSCALE 14
#define CT_WSCALE_FLAG 0x80 //启用了窗口放大
#define CT_WSCALE_UNKNOWN 0x40
#define CT_WSCALE_MASK 0xf


//取窗口放大因子
static uint8_t
tcp_get_wscale(const struct tcp_header *tcp)
{
    int len = TCP_OFFSET(tcp->tcp_ctl) * 4 - sizeof *tcp;//选项的长度
    const uint8_t *opt = (const uint8_t *)(tcp + 1);//选项的起始指针
    uint8_t wscale = 0;
    uint8_t optlen;

    while (len >= 3) {
        switch (*opt) {
        case TCPOPT_EOL://选项结束标记
            return wscale;
        case TCPOPT_NOP://空选项标记
            opt++;
            len--;
            break;
        case TCPOPT_WINDOW:
        	//窗口调整选项（最大14）
        	//TCP发送端在发送一个满窗口长度（最大65535字节）的数据后必须等待对端的ACK更新窗口后才能继续发送数据。
        	//在广域网中传输数据时，由于往返时间较长，发送端等待的时间也会较长，这样会使得TCP数据交互的速度大大降低
        	//（长肥管道现象）。使用窗口扩大选项可以使得发送端得到更大的通告窗口，这样就可以在ACK到来前发送更多的数据，
        	//减少了等待的时间，提高了数据传输效率。
            //　窗口扩大因子（shift.cnt）的大小是8bit，所以其值最大为255。使用窗口扩大选项后，真正的通告窗口大小 = TCP头
        	//中的窗口值＊2**shift.cnt。但由于TCP判断数据是新是旧的方法是：数据的序列号是否位于sun.una到sun.una + 2**31的范围内，
        	//如果是，则为新，否则为旧。故通告窗口大小在最大值不能大于或等于2**31，即max_windows <= 2**30。所以shitr.cnt的最大值为
        	//30 - 16 = 14。
            wscale = MIN(opt[2], TCP_MAX_WSCALE);
            wscale |= CT_WSCALE_FLAG;
            /* fall through */
        default://其它选项，取其长度，跳过此选项
            optlen = opt[1];
            if (optlen < 2) {
                optlen = 2;
            }
            len -= optlen;
            opt += optlen;
        }
    }

    return wscale;
}

static bool
tcp_bypass_seq_chk(struct conntrack *ct)
{
    if (!conntrack_get_tcp_seq_chk(ct)) {
        COVERAGE_INC(conntrack_tcp_seq_chk_bypass);
        return true;
    }
    return false;
}

//监测两端的tcp状态，变更自身的tcp状态
static enum ct_update_res
tcp_conn_update(struct conntrack *ct, struct conn *conn_,
                struct dp_packet *pkt, bool reply, long long now)
{
    struct conn_tcp *conn = conn_tcp_cast(conn_);
    struct tcp_header *tcp = dp_packet_l4(pkt);
    /* The peer that sent 'pkt' */
    //取出源
    struct tcp_peer *src = &conn->peer[reply ? 1 : 0];
    /* The peer that should receive 'pkt' */
    struct tcp_peer *dst = &conn->peer[reply ? 0 : 1];
    uint8_t sws = 0, dws = 0;
    uint16_t tcp_flags = TCP_FLAGS(tcp->tcp_ctl);//取出报文中的标记位

    uint16_t win = ntohs(tcp->tcp_winsz);//窗口大小
    uint32_t ack, end, seq, orig_seq;
    //此报文中包含的tcp负载（非ip total length - tcphdr length)
    uint32_t p_len = dp_packet_get_tcp_payload_length(pkt);

    //如果tcp标记位有误，返回更新无效
    if (tcp_invalid_flags(tcp_flags)) {
        COVERAGE_INC(conntrack_invalid_tcp_flags);
        return CT_UPDATE_INVALID;
    }

    //收到仅有syn标记，意识到是一条新流（如果之前dst,src状态还未超时至closed,将源目的均置为closed状态）
    if ((tcp_flags & (TCP_SYN | TCP_ACK)) == TCP_SYN) {
        if (dst->state >= CT_DPIF_TCPS_FIN_WAIT_2
            && src->state >= CT_DPIF_TCPS_FIN_WAIT_2) {
            src->state = dst->state = CT_DPIF_TCPS_CLOSED;
            return CT_UPDATE_NEW;
        } else if (src->state <= CT_DPIF_TCPS_SYN_SENT) {
            src->state = CT_DPIF_TCPS_SYN_SENT;
            conn_update_expiration(ct, &conn->up, CT_TM_TCP_FIRST_PACKET, now);
            return CT_UPDATE_VALID_NEW;
        }
    }

    //默认的sws,dws赋值
    if (src->wscale & CT_WSCALE_FLAG
        && dst->wscale & CT_WSCALE_FLAG
        && !(tcp_flags & TCP_SYN)) {

    	//之前已获取到wscale,本包不是syn(即不能更新），使用之前获取的值
        sws = src->wscale & CT_WSCALE_MASK;
        dws = dst->wscale & CT_WSCALE_MASK;

    } else if (src->wscale & CT_WSCALE_UNKNOWN
               && dst->wscale & CT_WSCALE_UNKNOWN
               && !(tcp_flags & TCP_SYN)) {

    	//之前未获取到，本包不是syn,使用最大扩大因子
        sws = TCP_MAX_WSCALE;
        dws = TCP_MAX_WSCALE;
    }

    /*
     * Sequence tracking algorithm from Guido van Rooij's paper:
     *   http://www.madison-gurkha.com/publications/tcp_filtering/
     *      tcp_filtering.ps
     */

    orig_seq = seq = ntohl(get_16aligned_be32(&tcp->tcp_seq));
    bool check_ackskew = true;
    if (src->state < CT_DPIF_TCPS_SYN_SENT) {//close,listen状态时

        /* First packet from this end. Set its state */

        ack = ntohl(get_16aligned_be32(&tcp->tcp_ack));

        end = seq + p_len;//本报文中最后一个字节对应的seq编号
        if (tcp_flags & TCP_SYN) {
            end++;//tcp syn占用字节
            if (dst->wscale & CT_WSCALE_FLAG) {
                src->wscale = tcp_get_wscale(tcp);//取本方向宣称的窗口扩大因子
                if (src->wscale & CT_WSCALE_FLAG) {
                    /* Remove scale factor from initial window */
                    sws = src->wscale & CT_WSCALE_MASK;
                    win = DIV_ROUND_UP((uint32_t) win, 1 << sws);//本方向指出的窗口大小
                    dws = dst->wscale & CT_WSCALE_MASK;
                } else {
                	//未看到wscale选项(没有搞懂下面这两行代码）
                    /* fixup other window */
                    dst->max_win <<= dst->wscale & CT_WSCALE_MASK;
                    /* in case of a retrans SYN|ACK */
                    dst->wscale = 0;
                }
            }
        }

        if (tcp_flags & TCP_FIN) {
            end++;//fin占用序列号
        }

        src->seqlo = seq;//记录源的序列号
        //之前是close,listen状态，现在有包来，在未检测syn的情况下，直接置为syn_send状态
        //状态处理很宽松。
        src->state = CT_DPIF_TCPS_SYN_SENT;
        /*
         * May need to slide the window (seqhi may have been set by
         * the crappy stack check or if we picked up the connection
         * after establishment)
         */
        if (src->seqhi == 1
                || SEQ_GEQ(end + MAX(1, dst->max_win << dws), src->seqhi)) {
            src->seqhi = end + MAX(1, dst->max_win << dws);
            /* We are either picking up a new connection or a connection which
             * was already in place.  We are more permissive in terms of
             * ackskew checking in these cases.
             */
            check_ackskew = false;
        }

        //更新最大窗口大小
        if (win > src->max_win) {
            src->max_win = win;
        }

    } else {
    	//其它状态情况下，仅需要提取ack,end的序列号
        ack = ntohl(get_16aligned_be32(&tcp->tcp_ack));
        end = seq + p_len;
        if (tcp_flags & TCP_SYN) {
            end++;
        }
        if (tcp_flags & TCP_FIN) {
            end++;
        }
    }

    //本方向的报文上没有ack标记，ack seq取dst方向的序列号。
    if ((tcp_flags & TCP_ACK) == 0) {
        /* Let it pass through the ack skew check */
        ack = dst->seqlo;
    } else if ((ack == 0
                && (tcp_flags & (TCP_ACK|TCP_RST)) == (TCP_ACK|TCP_RST))
               /* broken tcp stacks do not set ack */) {
        /* Many stacks (ours included) will set the ACK number in an
         * FIN|ACK if the SYN times out -- no sequence to ACK. */
        ack = dst->seqlo;//处理syn超时情况下，客户端发送的报文。
    }

    //如果本次没有数据，则选择不相信当前报文上的seq,采用之前的seq
    if (seq == end) {
        /* Ease sequencing restrictions on no data packets */
        seq = src->seqlo;
        end = seq;
    }

    //当前方向的ack被反方向的seqlo减。（即当前方向在确认反方向-ackskew前的报文
    //ip头部宣称的最大大小是2字节，故使用0xffff,而1500是作者考虑l2,l3头后加入的值
    int ackskew = check_ackskew ? dst->seqlo - ack : 0;
#define MAXACKWINDOW (0xffff + 1500)    /* 1500 is an arbitrary fudge factor */
    //end一定要在自已的窗口范围以内
    if ((SEQ_GEQ(src->seqhi, end)
        /* Last octet inside other's window space */
        && SEQ_GEQ(seq, src->seqlo - (dst->max_win << dws))
        /* Retrans: not more than one window back */
        && (ackskew >= -MAXACKWINDOW) //重传检查（比较随意，没有考虑窗口扩大因子）
        /* Acking not more than one reassembled fragment backwards */
        && (ackskew <= (MAXACKWINDOW << sws)) //确认报文一定在窗口范围内
        /* Acking not more than one window forward */
        && ((tcp_flags & TCP_RST) == 0 || orig_seq == src->seqlo
            || (orig_seq == src->seqlo + 1) || (orig_seq + 1 == src->seqlo)))
        || tcp_bypass_seq_chk(ct)) {
        /* Require an exact/+1 sequence match on resets when possible */

    	//学习更新的数据
        /* update max window */
        if (src->max_win < win) {
            src->max_win = win;
        }
        /* synchronize sequencing */
        if (SEQ_GT(end, src->seqlo)) {
            src->seqlo = end;
        }
        /* slide the window of what the other end can send */
        if (SEQ_GEQ(ack + (win << sws), dst->seqhi)) {
            dst->seqhi = ack + MAX((win << sws), 1);
        }

        //状态更新
        /* update states */
        if (tcp_flags & TCP_SYN && src->state < CT_DPIF_TCPS_SYN_SENT) {
                src->state = CT_DPIF_TCPS_SYN_SENT;
        }
        if (tcp_flags & TCP_FIN && src->state < CT_DPIF_TCPS_CLOSING) {
                src->state = CT_DPIF_TCPS_CLOSING;
        }
        if (tcp_flags & TCP_ACK) {
            if (dst->state == CT_DPIF_TCPS_SYN_SENT) {
                dst->state = CT_DPIF_TCPS_ESTABLISHED;
            } else if (dst->state == CT_DPIF_TCPS_CLOSING) {
                dst->state = CT_DPIF_TCPS_FIN_WAIT_2;
            }
        }

        //收到了rst，置为time_wait状态
        if (tcp_flags & TCP_RST) {
            src->state = dst->state = CT_DPIF_TCPS_TIME_WAIT;
        }

        if (src->state >= CT_DPIF_TCPS_FIN_WAIT_2
            && dst->state >= CT_DPIF_TCPS_FIN_WAIT_2) {
            //将connect换到对应的过期链上
            conn_update_expiration(ct, &conn->up, CT_TM_TCP_CLOSED, now);
        } else if (src->state >= CT_DPIF_TCPS_CLOSING
                   && dst->state >= CT_DPIF_TCPS_CLOSING) {
            conn_update_expiration(ct, &conn->up, CT_TM_TCP_FIN_WAIT, now);
        } else if (src->state < CT_DPIF_TCPS_ESTABLISHED
                   || dst->state < CT_DPIF_TCPS_ESTABLISHED) {
            conn_update_expiration(ct, &conn->up, CT_TM_TCP_OPENING, now);
        } else if (src->state >= CT_DPIF_TCPS_CLOSING
                   || dst->state >= CT_DPIF_TCPS_CLOSING) {
            conn_update_expiration(ct, &conn->up, CT_TM_TCP_CLOSING, now);
        } else {
            conn_update_expiration(ct, &conn->up, CT_TM_TCP_ESTABLISHED, now);
        }
    } else if ((dst->state < CT_DPIF_TCPS_SYN_SENT
                || dst->state >= CT_DPIF_TCPS_FIN_WAIT_2
                || src->state >= CT_DPIF_TCPS_FIN_WAIT_2)
               && SEQ_GEQ(src->seqhi + MAXACKWINDOW, end)
               /* Within a window forward of the originating packet */
               && SEQ_GEQ(seq, src->seqlo - MAXACKWINDOW)) {
               /* Within a window backward of the originating packet */

        /*
         * This currently handles three situations:
         *  1) Stupid stacks will shotgun SYNs before their peer
         *     replies.
         *  2) When PF catches an already established stream (the
         *     firewall rebooted, the state table was flushed, routes
         *     changed...)
         *  3) Packets get funky immediately after the connection
         *     closes (this should catch Solaris spurious ACK|FINs
         *     that web servers like to spew after a close)
         *
         * This must be a little more careful than the above code
         * since packet floods will also be caught here. We don't
         * update the TTL here to mitigate the damage of a packet
         * flood and so the same code can handle awkward establishment
         * and a loosened connection close.
         * In the establishment case, a correct peer response will
         * validate the connection, go through the normal state code
         * and keep updating the state TTL.
         */

        /* update max window */
        if (src->max_win < win) {
            src->max_win = win;
        }
        /* synchronize sequencing */
        if (SEQ_GT(end, src->seqlo)) {
            src->seqlo = end;
        }
        /* slide the window of what the other end can send */
        if (SEQ_GEQ(ack + (win << sws), dst->seqhi)) {
            dst->seqhi = ack + MAX((win << sws), 1);
        }

        /*
         * Cannot set dst->seqhi here since this could be a shotgunned
         * SYN and not an already established connection.
         */

        if (tcp_flags & TCP_FIN && src->state < CT_DPIF_TCPS_CLOSING) {
            src->state = CT_DPIF_TCPS_CLOSING;
        }

        //收到rst，置为time_wait状态
        if (tcp_flags & TCP_RST) {
            src->state = dst->state = CT_DPIF_TCPS_TIME_WAIT;
        }
    } else {
        COVERAGE_INC(conntrack_tcp_seq_chk_failed);
        //无效状态
        return CT_UPDATE_INVALID;
    }

    return CT_UPDATE_VALID;//状态有效
}

//检查是否可以新建连接（容许syn,及其它有ack标记的报文建立session)
static bool
tcp_valid_new(struct dp_packet *pkt)
{
    struct tcp_header *tcp = dp_packet_l4(pkt);
    uint16_t tcp_flags = TCP_FLAGS(tcp->tcp_ctl);

    //检查tcp标记是否无效
    if (tcp_invalid_flags(tcp_flags)) {
        return false;
    }

    /* A syn+ack is not allowed to create a connection.  We want to allow
     * totally new connections (syn) or already established, not partially
     * open (syn+ack). */
    //同时有syn+ack标记的，认为是无效的
    if ((tcp_flags & TCP_SYN) && (tcp_flags & TCP_ACK)) {
        return false;
    }

    return true;
}

//tcp新创建连接跟踪回调
static struct conn *
tcp_new_conn(struct conntrack *ct, struct dp_packet *pkt, long long now,
             uint32_t tp_id)
{
    struct conn_tcp* newconn = NULL;
    struct tcp_header *tcp = dp_packet_l4(pkt);
    struct tcp_peer *src, *dst;

    //取标记位
    uint16_t tcp_flags = TCP_FLAGS(tcp->tcp_ctl);

    newconn = xzalloc(sizeof *newconn);

    src = &newconn->peer[0];
    dst = &newconn->peer[1];

    //记录seq number
    src->seqlo = ntohl(get_16aligned_be32(&tcp->tcp_seq));
    //对端响应时，响应此seq number
    src->seqhi = src->seqlo + dp_packet_get_tcp_payload_length(pkt) + 1;

    if (tcp_flags & TCP_SYN) {
        src->seqhi++;//占用seq
        src->wscale = tcp_get_wscale(tcp);//提取窗口放大因子
    } else {
    	//非syn报文，窗口放大因子未知
        src->wscale = CT_WSCALE_UNKNOWN;
        dst->wscale = CT_WSCALE_UNKNOWN;
    }
    src->max_win = MAX(ntohs(tcp->tcp_winsz), 1);
    //启用了窗口放大因子
    if (src->wscale & CT_WSCALE_MASK) {
        /* Remove scale factor from initial window */
    	//计算窗口大小
        uint8_t sws = src->wscale & CT_WSCALE_MASK;
        src->max_win = DIV_ROUND_UP((uint32_t) src->max_win, 1 << sws);
    }

    if (tcp_flags & TCP_FIN) {
        src->seqhi++;//占用seq
    }

    //由于只有一方的流，对方我们暂不清楚，故设置为default值
    //这些值可以认为没有意义
    dst->seqhi = 1;
    dst->max_win = 1;
    src->state = CT_DPIF_TCPS_SYN_SENT;//进入syn_send状态（这个状态不是正确的，因为没有检查syn标记）
    dst->state = CT_DPIF_TCPS_CLOSED;//假设对方是closed状态

    newconn->up.tp_id = tp_id;
    conn_init_expiration(ct, &newconn->up, CT_TM_TCP_FIRST_PACKET, now);

    return &newconn->up;
}

static uint8_t
tcp_peer_to_protoinfo_flags(const struct tcp_peer *peer)
{
    uint8_t res = 0;

    if (peer->wscale & CT_WSCALE_FLAG) {
        res |= CT_DPIF_TCPF_WINDOW_SCALE;
    }

    if (peer->wscale & CT_WSCALE_UNKNOWN) {
        res |= CT_DPIF_TCPF_BE_LIBERAL;
    }

    return res;
}

static void
tcp_conn_get_protoinfo(const struct conn *conn_,
                       struct ct_dpif_protoinfo *protoinfo)
{
    const struct conn_tcp *conn = conn_tcp_cast(conn_);

    protoinfo->proto = IPPROTO_TCP;
    protoinfo->tcp.state_orig = conn->peer[0].state;
    protoinfo->tcp.state_reply = conn->peer[1].state;

    protoinfo->tcp.wscale_orig = conn->peer[0].wscale & CT_WSCALE_MASK;
    protoinfo->tcp.wscale_reply = conn->peer[1].wscale & CT_WSCALE_MASK;

    protoinfo->tcp.flags_orig = tcp_peer_to_protoinfo_flags(&conn->peer[0]);
    protoinfo->tcp.flags_reply = tcp_peer_to_protoinfo_flags(&conn->peer[1]);
}

struct ct_l4_proto ct_proto_tcp = {
    .new_conn = tcp_new_conn,
    .valid_new = tcp_valid_new,
    .conn_update = tcp_conn_update,
    .conn_get_protoinfo = tcp_conn_get_protoinfo,
};
