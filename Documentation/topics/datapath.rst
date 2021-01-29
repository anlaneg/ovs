..
      Licensed under the Apache License, Version 2.0 (the "License"); you may
      not use this file except in compliance with the License. You may obtain
      a copy of the License at

          http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.

      Convention for heading levels in Open vSwitch documentation:

      =======  Heading 0 (reserved for the title in a document)
      -------  Heading 1
      ~~~~~~~  Heading 2
      +++++++  Heading 3
      '''''''  Heading 4

      Avoid deeper levels because they do not render well.

=======================================
Open vSwitch Datapath Development Guide
=======================================
Open vSwitch Datapath 开发指导

The Open vSwitch kernel module allows flexible userspace control over
Open vSwitch 内核模块容许用户态在指定网络设上基于流，来控制包文处理。
flow-level packet processing on selected network devices.  It can be used to
implement a plain Ethernet switch, network device bonding, VLAN processing,
它被用于实现以太网交换机，网络设备堆叠，vlan处理，
network access control, flow-based network control, and so on.
网络访问控制和基于流的网络控制等等
The kernel module implements multiple "datapaths" (analogous to bridges), each
内核模块实现了多个datapath(类似于多个bridge)，
of which can have multiple "vports" (analogous to ports within a bridge).  Each
每个dataplane拥有多个vport(类似于一个bridge有多个port)
datapath also has associated with it a "flow table" that userspace populates
每个dataplane和flow table相关联，flow table由用户态依据flows结构填充，flow中的值来源于报文头，其元数据，以及一组动作
with "flows" that map from keys based on packet headers and metadata to sets of
actions.  The most common action forwards the packet to another vport; other
actions are also implemented.
最常见的动作是将报言语转发到另一个vport,当然还有其它的动作也都已被实现

When a packet arrives on a vport, the kernel module processes it by extracting
当一个报文到达一个vport,内核模块会处理它：提取报文的flow信息，并在flow table中进行查询。
its flow key and looking it up in the flow table.  If there is a matching flow,
如果发现flow table中有匹配，
it executes the associated actions.  If there is no match, it queues the packet
它会执行对应的规则，如果发现flow table中无匹配，它会将此报文按序传递给用户态做处理（做为报文处理的一部分，用户态
to userspace for processing (as part of its processing, userspace will likely
set up a flow to handle further packets of the same type entirely in-kernel).
极有可能会安装一个新的flow，以便完全在内核中处理后续出现的相同类型的报文）

Flow Key Compatibility
----------------------
flow key的兼容性

Network protocols evolve over time.  New protocols become important and
网络协议随时间发展，新的协议会变的重要，已存在的协议会变得不那么重要。
existing protocols lose their prominence.  For the Open vSwitch kernel module
to remain relevant, it must be possible for newer versions to parse additional
为了使Open vSwitch内核模块保持合乎时宜，它就不得不为了新版协议而增加flow解析的key.
protocols as part of the flow key.  It might even be desirable, someday, to
drop support for parsing protocols that have become obsolete.  Therefore, the
而某天放弃对某个过时的协议的解析也是合理的。
Netlink interface to Open vSwitch is designed to allow carefully written
userspace applications to work with any version of the flow key, past or
future.
因此Open vSwitch的netlink接口一直都被设计为可与用户态程序一起支持任意版本的flow key。

To support this forward and backward compatibility, whenever the kernel module
passes a packet to userspace, it also passes along the flow key that it parsed
为了支持这个前向，后向兼容，内核模块传给一个报文给用户态时，它也会传递它解析好的对应的flow key。
from the packet.  Userspace then extracts its own notion of a flow key from the
packet and compares it against the kernel-provided version:
用户态自报文中提取自已想要flow key后，可以和内核提供的版本进行比对：

- If userspace's notion of the flow key for the packet matches the kernel's,
  then nothing special is necessary.

如果用户态想要的flow key与内核的匹配，那就不需要特别处理

- If the kernel's flow key includes more fields than the userspace version of
  the flow key, for example if the kernel decoded IPv6 headers but userspace
  stopped at the Ethernet type (because it does not understand IPv6), then
  again nothing special is necessary.  Userspace can still set up a flow in the
  usual way, as long as it uses the kernel-provided flow key to do it.
  
  如果内核的flow key 的字段多于用户态的flow key,举个例子，如果内核解码ipv6头，但用户态只解码到以太帧协议类型（因为它不认识Ipv6)
  那也不需要特别处理，用户态仍能用kernel提供的flow key 像平常一样安装一个流。
- If the userspace flow key includes more fields than the kernel's, for example
  if userspace decoded an IPv6 header but the kernel stopped at the Ethernet
  type, then userspace can forward the packet manually, without setting up a
  flow in the kernel.  This case is bad for performance because every packet
  that the kernel considers part of the flow must go to userspace, but the
  forwarding behavior is correct.  (If userspace can determine that the values
  of the extra fields would not affect forwarding behavior, then it could set
  up a flow anyway.)
  如果用户态flow key的字段多于内核，举个例子用户态解决了Ipv6头，但内核只解码到以态帧协议类型，那么
  用户态可以手工转发包文，但不安装流到kernel.这种情况性能很差因为内核考虑此流的每个部分都需要去用户态，但
  这个转发性为是对的（如果用户态能够检测这此额外字段的值，不会影响转发行为，那么它可以安装一个流）

How flow keys evolve over time is important to making this work, so
the following sections go into detail.

flow key如何随时间的推移而变化是很重要的工作，所以下面详细描述

Flow Key Format
---------------
flow key 格式

A flow key is passed over a Netlink socket as a sequence of Netlink attributes.
flow key做为一组Netlink属性在Netlink socket上传递。
Some attributes represent packet metadata, defined as any information about a
一些属性反映了报文的元数据，它们被定义为所有从报文本身无法提取出的信息。例如，报文从哪个vport上收到。
packet that cannot be extracted from the packet itself, e.g. the vport on which
the packet was received.  Most attributes, however, are extracted from headers
within the packet, e.g. source and destination addresses from Ethernet, IP, or
TCP headers.
但大多数属性是从报文头上提取出来的，例如来自链路层，ip层或者tcp头部的源及目的地址

The ``<linux/openvswitch.h>`` header file defines the exact format of the flow
key attributes.  For informal explanatory purposes here, we write them as
‘<linux/openvswitch.h>头文件定义了正确的flow key属性格式，这里出于更好的解释的目的，我们将它们
comma-separated strings, with parentheses indicating arguments and nesting.
写成用逗号分格的字符串，用括号来指明参数与嵌套
For example, the following could represent a flow key corresponding to a TCP
packet that arrived on vport 1::
举个例子，下面的flow key表示vport 1口收到一个tcp报文

    in_port(1), eth(src=e0:91:f5:21:d0:b2, dst=00:02:e3:0f:80:a4),
    eth_type(0x0800), ipv4(src=172.16.0.20, dst=172.18.0.52, proto=6, tos=0,
    frag=no), tcp(src=49163, dst=80)

Often we ellipsize arguments not important to the discussion, e.g.::
通常我们会省略掉在讨论中不重要的参数，例如

    in_port(1), eth(...), eth_type(0x0800), ipv4(...), tcp(...)

Wildcarded Flow Key Format
--------------------------
flow key格式通配

A wildcarded flow is described with two sequences of Netlink attributes passed
over the Netlink socket. A flow key, exactly as described above, and an
optional corresponding flow mask.
通配flow通过netlink socket传递时采用2个netlink属性序列描述，flow key和上面描述一样，另一个是flow mask

A wildcarded flow can represent a group of exact match flows. Each ``1`` bit
in the mask specifies an exact match with the corresponding bit in the flow key.
A ``0`` bit specifies a don't care bit, which will match either a ``1`` or
``0`` bit of an incoming packet. Using a wildcarded flow can improve the flow
set up rate by reducing the number of new flows that need to be processed by
the user space program.
一个通配flow能够表示一组精确匹配，每个在mask中的'1'位指定对应的在flow key中的位需要精确匹配。
‘0’位指定为非关心位，它可以匹配对应位的'1'或者‘0’中的任意一个。采用通配flow能够通过减少用户态
程序下发的flow数量来改进flow安装速率。

Support for the mask Netlink attribute is optional for both the kernel and user
space program. The kernel can ignore the mask attribute, installing an exact
match flow, or reduce the number of don't care bits in the kernel to less than
what was specified by the user space program. In this case, variations in bits
that the kernel does not implement will simply result in additional flow
setups.  The kernel module will also work with user space programs that neither
support nor supply flow mask attributes.
支持netlink属性mask对kernel和用户态程序都是可选的，kernel可以忽略mask属性，而安装一个精确匹配
的流，或者相对用户态程序下发的流而言，更少的非关心位数，在这种情况下，kernel没有实现的变动位，将导致需要
增加安装流。kernel模块也能和用户态不支持mask属性的应用程序一起工作。

Since the kernel may ignore or modify wildcard bits, it can be difficult for
the userspace program to know exactly what matches are installed. There are two
possible approaches: reactively install flows as they miss the kernel flow
table (and therefore not attempt to determine wildcard changes at all) or use
the kernel's response messages to determine the installed wildcards.
一旦用核可能忽略或者修改通配位，用户态程序就很难知道安装了怎样的精确匹配，有两种可能的方法，
反射性安装，因为它们错误了kernel的flow table(这种不尝试检测通配改了什么） 或者
用内核的反馈消息来检测安装的通配

When interacting with userspace, the kernel should maintain the match portion
of the key exactly as originally installed. This will provides a handle to
identify the flow for all future operations. However, when reporting the mask
of an installed flow, the mask should include any restrictions imposed by the
kernel.
与用户态交互时，内核应维护一份key的像原始安装一样的精确匹配。这个为流将来的操作提供标识，当
report一个安装的流的mask,这个mask应包含任何限制？？？？

The behavior when using overlapping wildcarded flows is undefined. It is the
responsibility of the user space program to ensure that any incoming packet can
match at most one flow, wildcarded or not. The current implementation performs
best-effort detection of overlapping wildcarded flows and may reject some but
not all of them. However, this behavior may change in future versions.
重叠通符流的行为是无定义的，用户态程序对确保任何进来的报文最多只匹配一条flow负最大责任，通配或者非通配
当前实现尽最大努力检测了通配重叠然后拒绝掉，但不是全部，这个行为在将来版本可能会发生变化。

Unique Flow Identifiers
-----------------------
唯一流标识

An alternative to using the original match portion of a key as the handle for
flow identification is a unique flow identifier, or "UFID". UFIDs are optional
for both the kernel and user space program.
采用原始配置的那一份key作为flow的唯一流标识，或者用ufid,ufid对kenrel和用户态程序是可选的。

User space programs that support UFID are expected to provide it during flow
setup in addition to the flow, then refer to the flow using the UFID for all
future operations. The kernel is not required to index flows by the original
flow key if a UFID is specified.
用户态程序被期待在flow被安装时提供ufid来支持ufid，这样后续操作将通过用ufid来引用flow,如果ufid被
指定，kernel就不需要通过原始的flow key来索引flow了

Basic Rule for Evolving Flow Keys
---------------------------------
flow key演进的基本规则

Some care is needed to really maintain forward and backward compatibility for
applications that follow the rules listed under "Flow key compatibility" above.
维护前向，后向兼容需要考虑的规则被列在下面。

The basic rule is obvious:

    New network protocol support must only supplement existing flow key
    attributes.  It must not change the meaning of already defined flow key
    attributes.
    
    新的网络协议的支持必须仅仅补充已存在的flow key属性，它不能改变已存在的flow key属性的含义

This rule does have less-obvious consequences so it is worth working through a
few examples.  Suppose, for example, that the kernel module did not already
implement VLAN parsing.  Instead, it just interpreted the 802.1Q TPID
(``0x8100``) as the Ethertype then stopped parsing the packet.  The flow key
for any packet with an 802.1Q header would look essentially like this, ignoring
metadata::

这个规则没有明显的后果，因此通过几个例子说明是值得的。例如，假设内核模块还没有实现vlan解析，于是，
它通过指明以太网协议类型为0x8100来指代802.1q并停止继续解析报文。flow key对任何有802.1q头的报文本质上
和下面这个一样，除了原数据

    eth(...), eth_type(0x8100)

Naively, to add VLAN support, it makes sense to add a new "vlan" flow key
attribute to contain the VLAN tag, then continue to decode the encapsulated
headers beyond the VLAN tag using the existing field definitions.  With this
change, a TCP packet in VLAN 10 would have a flow key much like this::
要添加vlan支持，需要新添加一个'vlan' flow key属性去包含vlan 标签，然后用位于vlan tag后面的已
存在的字段来继续解码头部的封装。加入这个改变后，一个有flow key的vlan 10的tcp报文象这样。

    eth(...), vlan(vid=10, pcp=0), eth_type(0x0800), ip(proto=6, ...), tcp(...)

But this change would negatively affect a userspace application that has not
been updated to understand the new "vlan" flow key attribute.  The application
could, following the flow compatibility rules above, ignore the "vlan"
attribute that it does not understand and therefore assume that the flow
contained IP packets.  This is a bad assumption (the flow only contains IP
packets if one parses and skips over the 802.1Q header) and it could cause the
application's behavior to change across kernel versions even though it follows
the compatibility rules.
但是这个改变会对不认识新的'vlan' flow key属性的用户态程序产生负面影响。这个应用程序可以，依据上面
flow兼容规则，忽略它不认识的'vlan'属性，。

The solution is to use a set of nested attributes.  This is, for example, why
802.1Q support uses nested attributes.  A TCP packet in VLAN 10 is actually
expressed as::

    eth(...), eth_type(0x8100), vlan(vid=10, pcp=0), encap(eth_type(0x0800),
    ip(proto=6, ...), tcp(...)))

Notice how the ``eth_type``, ``ip``, and ``tcp`` flow key attributes are nested
inside the ``encap`` attribute.  Thus, an application that does not understand
the ``vlan`` key will not see either of those attributes and therefore will not
misinterpret them.  (Also, the outer ``eth_type`` is still ``0x8100``, not
changed to ``0x0800``)

Handling Malformed Packets
--------------------------

Don't drop packets in the kernel for malformed protocol headers, bad checksums,
etc.  This would prevent userspace from implementing a simple Ethernet switch
that forwards every packet.

Instead, in such a case, include an attribute with "empty" content.  It doesn't
matter if the empty content could be valid protocol values, as long as those
values are rarely seen in practice, because userspace can always forward all
packets with those values to userspace and handle them individually.

For example, consider a packet that contains an IP header that indicates
protocol 6 for TCP, but which is truncated just after the IP header, so that
the TCP header is missing.  The flow key for this packet would include a tcp
attribute with all-zero ``src`` and ``dst``, like this::

    eth(...), eth_type(0x0800), ip(proto=6, ...), tcp(src=0, dst=0)

As another example, consider a packet with an Ethernet type of 0x8100,
indicating that a VLAN TCI should follow, but which is truncated just after the
Ethernet type.  The flow key for this packet would include an all-zero-bits
vlan and an empty encap attribute, like this::

    eth(...), eth_type(0x8100), vlan(0), encap()

Unlike a TCP packet with source and destination ports 0, an all-zero-bits VLAN
TCI is not that rare, so the CFI bit (aka VLAN_TAG_PRESENT inside the kernel)
is ordinarily set in a vlan attribute expressly to allow this situation to be
distinguished.  Thus, the flow key in this second example unambiguously
indicates a missing or malformed VLAN TCI.

Other Rules
-----------

The other rules for flow keys are much less subtle:

- Duplicate attributes are not allowed at a given nesting level.

- Ordering of attributes is not significant.

- When the kernel sends a given flow key to userspace, it always composes it
  the same way.  This allows userspace to hash and compare entire flow keys
  that it may not be able to fully interpret.

Coding Rules
------------

Implement the headers and codes for compatibility with older kernel in
``linux/compat/`` directory.  All public functions should be exported using
``EXPORT_SYMBOL`` macro.  Public function replacing the same-named kernel
function should be prefixed with ``rpl_``.  Otherwise, the function should be
prefixed with ``ovs_``.  For special case when it is not possible to follow
this rule (e.g., the ``pskb_expand_head()`` function), the function name must
be added to ``linux/compat/build-aux/export-check-allowlist``, otherwise, the
compilation check ``check-export-symbol`` will fail.
