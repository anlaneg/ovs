/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013, 2016 Nicira, Inc.
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
#include <stdlib.h>
#include <string.h>

#include "dp-packet.h"
#include "netdev-afxdp.h"
#include "netdev-dpdk.h"
#include "openvswitch/dynamic-string.h"
#include "util.h"

static void
dp_packet_init__(struct dp_packet *b, size_t allocated, enum dp_packet_source source)//初始化设置packet
{
    dp_packet_set_allocated(b, allocated);
    b->source = source;
    dp_packet_reset_offsets(b);
    pkt_metadata_init(&b->md, 0);
    dp_packet_reset_cutlen(b);
    dp_packet_reset_offload(b);
    /* Initialize implementation-specific fields of dp_packet. */
    dp_packet_init_specific(b);
    /* By default assume the packet type to be Ethernet. */
    b->packet_type = htonl(PT_ETH);
}

static void
dp_packet_use__(struct dp_packet *b, void *base, size_t allocated,
             enum dp_packet_source source)
{
    dp_packet_set_base(b, base);
    dp_packet_set_data(b, base);
    dp_packet_set_size(b, 0);

    dp_packet_init__(b, allocated, source);
}

/* Initializes 'b' as an empty dp_packet that contains the 'allocated' bytes of
 * memory starting at 'base'.  'base' should be the first byte of a region
 * obtained from malloc().  It will be freed (with free()) if 'b' is resized or
 * freed. */
void
dp_packet_use(struct dp_packet *b, void *base, size_t allocated)
//使用malloc类型管理packet,base是packet的起始内存，allocated是申请字节数
{
    dp_packet_use__(b, base, allocated, DPBUF_MALLOC);
}

#if HAVE_AF_XDP
/* Initialize 'b' as an empty dp_packet that contains
 * memory starting at AF_XDP umem base.
 */
void
dp_packet_use_afxdp(struct dp_packet *b, void *data, size_t allocated,
                    size_t headroom)
{
    dp_packet_set_base(b, (char *)data - headroom);
    dp_packet_set_data(b, data);
    dp_packet_set_size(b, 0);

    dp_packet_init__(b, allocated, DPBUF_AFXDP);
}
#endif

/* Initializes 'b' as an empty dp_packet that contains the 'allocated' bytes of
 * memory starting at 'base'.  'base' should point to a buffer on the stack.
 * (Nothing actually relies on 'base' being allocated on the stack.  It could
 * be static or malloc()'d memory.  But stack space is the most common use
 * case.)
 *
 * 'base' should be appropriately aligned.  Using an array of uint32_t or
 * uint64_t for the buffer is a reasonable way to ensure appropriate alignment
 * for 32- or 64-bit data.
 *
 * An dp_packet operation that requires reallocating data will copy the provided
 * buffer into a malloc()'d buffer.  Thus, it is wise to call dp_packet_uninit()
 * on an dp_packet initialized by this function, so that if it expanded into the
 * heap, that memory is freed. */
void
dp_packet_use_stub(struct dp_packet *b, void *base, size_t allocated)//使用stub类型管理packet
{
    dp_packet_use__(b, base, allocated, DPBUF_STUB);
}

/* Initializes 'b' as an dp_packet whose data starts at 'data' and continues for
 * 'size' bytes.  This is appropriate for an dp_packet that will be used to
 * inspect existing data, without moving it around or reallocating it, and
 * generally without modifying it at all.
 *
 * An dp_packet operation that requires reallocating data will assert-fail if this
 * function was used to initialize it. */
void
dp_packet_use_const(struct dp_packet *b, const void *data, size_t size)//使用stack方式创建dp_packet
{
    dp_packet_use__(b, CONST_CAST(void *, data), size, DPBUF_STACK);
    dp_packet_set_size(b, size);
}

/* Initializes 'b' as a DPDK dp-packet, which must have been allocated from a
 * DPDK memory pool. */
void
//使用dpdk类型管理packet
dp_packet_init_dpdk(struct dp_packet *b)
{
    b->source = DPBUF_DPDK;
}

/* Initializes 'b' as an empty dp_packet with an initial capacity of 'size'
 * bytes. */
void
dp_packet_init(struct dp_packet *b, size_t size)
{
    dp_packet_use(b, size ? xmalloc(size) : NULL, size);
}

/* Frees memory that 'b' points to. */
void
dp_packet_uninit(struct dp_packet *b)
{
    if (b) {
        if (b->source == DPBUF_MALLOC) {
            free(dp_packet_base(b));
        } else if (b->source == DPBUF_DPDK) {
#ifdef DPDK_NETDEV
            /* If this dp_packet was allocated by DPDK it must have been
             * created as a dp_packet */
            free_dpdk_buf((struct dp_packet*) b);
#endif
        } else if (b->source == DPBUF_AFXDP) {
            free_afxdp_buf(b);
        }
    }
}

/* Creates and returns a new dp_packet with an initial capacity of 'size'
 * bytes. */
struct dp_packet *
dp_packet_new(size_t size)
{
    struct dp_packet *b = xmalloc(sizeof *b);
    dp_packet_init(b, size);
    return b;
}

/* Creates and returns a new dp_packet with an initial capacity of 'size +
 * headroom' bytes, reserving the first 'headroom' bytes as headroom. */
//申请一个报文空间，申请时预留给定的headroom大小
struct dp_packet *
dp_packet_new_with_headroom(size_t size, size_t headroom)
{
    struct dp_packet *b = dp_packet_new(size + headroom);
    dp_packet_reserve(b, headroom);
    return b;
}

/* Creates and returns a new dp_packet that initially contains a copy of the
 * 'dp_packet_size(buffer)' bytes of data starting at 'buffer->data' with no headroom or
 * tailroom. */
struct dp_packet *
dp_packet_clone(const struct dp_packet *buffer)//报文copy
{
    return dp_packet_clone_with_headroom(buffer, 0);
}

/* Creates and returns a new dp_packet whose data are copied from 'buffer'.
 * The returned dp_packet will additionally have 'headroom' bytes of
 * headroom. */
struct dp_packet *
dp_packet_clone_with_headroom(const struct dp_packet *buffer, size_t headroom)//创建相同报文
{
    struct dp_packet *new_buffer;
    uint32_t mark;

    //创建buffer的一份幅本，幅本建立时预留headroom大小。
    new_buffer = dp_packet_clone_data_with_headroom(dp_packet_data(buffer),
                                                 dp_packet_size(buffer),
                                                 headroom);
    /* Copy the following fields into the returned buffer: l2_pad_size,
     * l2_5_ofs, l3_ofs, l4_ofs, cutlen, packet_type and md. */
    //控制变量copy
    memcpy(&new_buffer->l2_pad_size, &buffer->l2_pad_size,
            sizeof(struct dp_packet) -
            offsetof(struct dp_packet, l2_pad_size));

    *dp_packet_ol_flags_ptr(new_buffer) = *dp_packet_ol_flags_ptr(buffer);
    *dp_packet_ol_flags_ptr(new_buffer) &= DP_PACKET_OL_SUPPORTED_MASK;

    if (dp_packet_rss_valid(buffer)) {
        dp_packet_set_rss_hash(new_buffer, dp_packet_get_rss_hash(buffer));
    }
    if (dp_packet_has_flow_mark(buffer, &mark)) {
        dp_packet_set_flow_mark(new_buffer, mark);
    }

    return new_buffer;
}

/* Creates and returns a new dp_packet that initially contains a copy of the
 * 'size' bytes of data starting at 'data' with no headroom or tailroom. */
struct dp_packet *
dp_packet_clone_data(const void *data, size_t size)
{
    return dp_packet_clone_data_with_headroom(data, size, 0);
}

/* Creates and returns a new dp_packet that initially contains 'headroom' bytes of
 * headroom followed by a copy of the 'size' bytes of data starting at
 * 'data'. */
//报文copy,并创建相同的headroom空间
struct dp_packet *
dp_packet_clone_data_with_headroom(const void *data, size_t size, size_t headroom)
{
    struct dp_packet *b = dp_packet_new_with_headroom(size, headroom);
    dp_packet_put(b, data, size);//完成报文copy
    return b;
}

static void
dp_packet_copy__(struct dp_packet *b, uint8_t *new_base,
              size_t new_headroom, size_t new_tailroom)
{
    const uint8_t *old_base = dp_packet_base(b);
    size_t old_headroom = dp_packet_headroom(b);
    size_t old_tailroom = dp_packet_tailroom(b);
    size_t copy_headroom = MIN(old_headroom, new_headroom);
    size_t copy_tailroom = MIN(old_tailroom, new_tailroom);

    memcpy(&new_base[new_headroom - copy_headroom],
           &old_base[old_headroom - copy_headroom],
           copy_headroom + dp_packet_size(b) + copy_tailroom);
}

/* Reallocates 'b' so that it has exactly 'new_headroom' and 'new_tailroom'
 * bytes of headroom and tailroom, respectively. */
//增长packet，使其headroom为new_headroom,使其tailroom为new_tailroom
void
dp_packet_resize(struct dp_packet *b, size_t new_headroom, size_t new_tailroom)
{
    void *new_base, *new_data;
    size_t new_allocated;

    new_allocated = new_headroom + dp_packet_size(b) + new_tailroom;

    switch (b->source) {
    case DPBUF_DPDK:
        OVS_NOT_REACHED();//dpdk不能进入此函数，进入即报错(dpdk在基头部预存了64字节）

    case DPBUF_MALLOC:
        if (new_headroom == dp_packet_headroom(b)) {//头部大小合适时，采用realloc
            new_base = xrealloc(dp_packet_base(b), new_allocated);
        } else {
            new_base = xmalloc(new_allocated);
            dp_packet_copy__(b, new_base, new_headroom, new_tailroom);
            //重新申请空间，将旧的copy到新的，保证new_headroom,new_tailroom
            free(dp_packet_base(b));//释放内存
        }
        break;

    case DPBUF_STACK://stack上无法增加
        OVS_NOT_REACHED();

    case DPBUF_AFXDP:
        OVS_NOT_REACHED();

    case DPBUF_STUB://增大，但不释放旧的
        b->source = DPBUF_MALLOC;
        new_base = xmalloc(new_allocated);
        dp_packet_copy__(b, new_base, new_headroom, new_tailroom);
        break;

    default:
        OVS_NOT_REACHED();
    }

    dp_packet_set_allocated(b, new_allocated);
    dp_packet_set_base(b, new_base);

    new_data = (char *) new_base + new_headroom;
    if (dp_packet_data(b) != new_data) {
        dp_packet_set_data(b, new_data);
    }
}

/* Ensures that 'b' has room for at least 'size' bytes at its tail end,
 * reallocating and copying its data if necessary.  Its headroom, if any, is
 * preserved. */
void
dp_packet_prealloc_tailroom(struct dp_packet *b, size_t size)
{
    if ((size && !dp_packet_base(b)) || (size > dp_packet_tailroom(b))) {
        dp_packet_resize(b, dp_packet_headroom(b), MAX(size, 64));
    }
}

/* Ensures that 'b' has room for at least 'size' bytes at its head,
 * reallocating and copying its data if necessary.  Its tailroom, if any, is
 * preserved. */
void
dp_packet_prealloc_headroom(struct dp_packet *b, size_t size)//在报文头部空出size字节（即保证headroom>=size)
{
    if (size > dp_packet_headroom(b)) {//要求的size比headroom大
        dp_packet_resize(b, MAX(size, 64), dp_packet_tailroom(b));//扩充headroom
    }
}

/* Shifts all of the data within the allocated space in 'b' by 'delta' bytes.
 * For example, a 'delta' of 1 would cause each byte of data to move one byte
 * forward (from address 'p' to 'p+1'), and a 'delta' of -1 would cause each
 * byte to move one byte backward (from 'p' to 'p-1'). */
void
dp_packet_shift(struct dp_packet *b, int delta)
{
    ovs_assert(delta > 0 ? delta <= dp_packet_tailroom(b)
               : delta < 0 ? -delta <= dp_packet_headroom(b)
               : true);

    if (delta != 0) {
        char *dst = (char *) dp_packet_data(b) + delta;
        memmove(dst, dp_packet_data(b), dp_packet_size(b));
        dp_packet_set_data(b, dst);
    }
}

/* Appends 'size' bytes of data to the tail end of 'b', reallocating and
 * copying its data if necessary.  Returns a pointer to the first byte of the
 * new data, which is left uninitialized. */
void *
dp_packet_put_uninit(struct dp_packet *b, size_t size)
{
    void *p;
    dp_packet_prealloc_tailroom(b, size);
    p = dp_packet_tail(b);
    dp_packet_set_size(b, dp_packet_size(b) + size);
    return p;
}

/* Appends 'size' zeroed bytes to the tail end of 'b'.  Data in 'b' is
 * reallocated and copied if necessary.  Returns a pointer to the first byte of
 * the data's location in the dp_packet. */
void *
dp_packet_put_zeros(struct dp_packet *b, size_t size)
{
    void *dst = dp_packet_put_uninit(b, size);
    memset(dst, 0, size);
    return dst;
}

/* Appends the 'size' bytes of data in 'p' to the tail end of 'b'.  Data in 'b'
 * is reallocated and copied if necessary.  Returns a pointer to the first
 * byte of the data's location in the dp_packet. */
void *
dp_packet_put(struct dp_packet *b, const void *p, size_t size)
{
    void *dst = dp_packet_put_uninit(b, size);
    memcpy(dst, p, size);
    return dst;
}

/* Parses as many pairs of hex digits as possible (possibly separated by
 * spaces) from the beginning of 's', appending bytes for their values to 'b'.
 * Returns the first character of 's' that is not the first of a pair of hex
 * digits.  If 'n' is nonnull, stores the number of bytes added to 'b' in
 * '*n'. */
char *
dp_packet_put_hex(struct dp_packet *b, const char *s, size_t *n)
{
    size_t initial_size = dp_packet_size(b);
    for (;;) {
        uint8_t byte;
        bool ok;

        s += strspn(s, " \t\r\n");
        byte = hexits_value(s, 2, &ok);
        if (!ok) {
            if (n) {
                *n = dp_packet_size(b) - initial_size;
            }
            return CONST_CAST(char *, s);
        }

        dp_packet_put(b, &byte, 1);
        s += 2;
    }
}

/* Reserves 'size' bytes of headroom so that they can be later allocated with
 * dp_packet_push_uninit() without reallocating the dp_packet. */
void
dp_packet_reserve(struct dp_packet *b, size_t size)
{
    ovs_assert(!dp_packet_size(b));
    dp_packet_prealloc_tailroom(b, size);
    dp_packet_set_data(b, (char*)dp_packet_data(b) + size);
}

/* Reserves 'headroom' bytes at the head and 'tailroom' at the end so that
 * they can be later allocated with dp_packet_push_uninit() or
 * dp_packet_put_uninit() without reallocating the dp_packet. */
void
dp_packet_reserve_with_tailroom(struct dp_packet *b, size_t headroom,
                             size_t tailroom)
{
    ovs_assert(!dp_packet_size(b));
    dp_packet_prealloc_tailroom(b, headroom + tailroom);
    dp_packet_set_data(b, (char*)dp_packet_data(b) + headroom);
}

/* Prefixes 'size' bytes to the head end of 'b', reallocating and copying its
 * data if necessary.  Returns a pointer to the first byte of the data's
 * location in the dp_packet.  The new data is left uninitialized. */
//在packet头部先空出size大小，不初始化。
void *
dp_packet_push_uninit(struct dp_packet *b, size_t size)
{
    dp_packet_prealloc_headroom(b, size);
    dp_packet_set_data(b, (char*)dp_packet_data(b) - size);//调速data偏移量
    dp_packet_set_size(b, dp_packet_size(b) + size);//增大报文数据大小
    return dp_packet_data(b);//返回新的数据起始位置
}

/* Prefixes 'size' zeroed bytes to the head end of 'b', reallocating and
 * copying its data if necessary.  Returns a pointer to the first byte of the
 * data's location in the dp_packet. */
//在头部空出size字节，并将这size字节置为0
void *
dp_packet_push_zeros(struct dp_packet *b, size_t size)
{
    void *dst = dp_packet_push_uninit(b, size);//在头部空出size字节，并将这size字节置为0
    memset(dst, 0, size);
    return dst;
}

/* Copies the 'size' bytes starting at 'p' to the head end of 'b', reallocating
 * and copying its data if necessary.  Returns a pointer to the first byte of
 * the data's location in the dp_packet. */
//在头部空出size字节，在这size字节里填充b
void *
dp_packet_push(struct dp_packet *b, const void *p, size_t size)
{
    void *dst = dp_packet_push_uninit(b, size);
    memcpy(dst, p, size);
    return dst;
}

/* Returns the data in 'b' as a block of malloc()'d memory and frees the buffer
 * within 'b'.  (If 'b' itself was dynamically allocated, e.g. with
 * dp_packet_new(), then it should still be freed with, e.g., dp_packet_delete().) */
void *
dp_packet_steal_data(struct dp_packet *b)
{
    void *p;
    ovs_assert(b->source != DPBUF_DPDK);
    ovs_assert(b->source != DPBUF_AFXDP);

    if (b->source == DPBUF_MALLOC && dp_packet_data(b) == dp_packet_base(b)) {
        p = dp_packet_data(b);
    } else {
        p = xmemdup(dp_packet_data(b), dp_packet_size(b));
        if (b->source == DPBUF_MALLOC) {
            free(dp_packet_base(b));
        }
    }
    dp_packet_set_base(b, NULL);
    dp_packet_set_data(b, NULL);
    return p;
}

static inline void
dp_packet_adjust_layer_offset(uint16_t *offset, int increment)
{
    if (*offset != UINT16_MAX) {
        *offset += increment;
    }
}

/* Adjust the size of the l2_5 portion of the dp_packet, updating the l2
 * pointer and the layer offsets.  The caller is responsible for
 * modifying the contents. */
void *
dp_packet_resize_l2_5(struct dp_packet *b, int increment)//调整报文数据占用空间及offset设置
{
    if (increment >= 0) {
        dp_packet_push_uninit(b, increment);//头部直加increment
    } else {
        dp_packet_pull(b, -increment);//数据缩进increment
    }

    /* Adjust layer offsets after l2_5. */
    dp_packet_adjust_layer_offset(&b->l3_ofs, increment);//变更l3_ofs
    dp_packet_adjust_layer_offset(&b->l4_ofs, increment);//变更l4_ofs

    return dp_packet_data(b);
}

/* Adjust the size of the l2 portion of the dp_packet, updating the l2
 * pointer and the layer offsets.  The caller is responsible for
 * modifying the contents. */
//更新报文空间占用，更新l3,l4 offset
void *
dp_packet_resize_l2(struct dp_packet *b, int increment)
{
    dp_packet_resize_l2_5(b, increment);
    dp_packet_adjust_layer_offset(&b->l2_5_ofs, increment);//变更l2_5_ofs
    return dp_packet_data(b);
}
