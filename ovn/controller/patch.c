/* Copyright (c) 2015, 2016, 2017 Nicira, Inc.
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

#include "patch.h"

#include "hash.h"
#include "lflow.h"
#include "lib/vswitch-idl.h"
#include "lport.h"
#include "openvswitch/hmap.h"
#include "openvswitch/vlog.h"
#include "ovn-controller.h"

VLOG_DEFINE_THIS_MODULE(patch);

static char *
patch_port_name(const char *src, const char *dst)
{
    return xasprintf("patch-%s-to-%s", src, dst);
}

/* Return true if 'port' is a patch port with the specified 'peer'. */
static bool
match_patch_port(const struct ovsrec_port *port, const char *peer)
{
    for (size_t i = 0; i < port->n_interfaces; i++) {
        struct ovsrec_interface *iface = port->interfaces[i];
        if (strcmp(iface->type, "patch")) {
        	//必须是patch口
            continue;
        }
        const char *iface_peer = smap_get(&iface->options, "peer");
        if (iface_peer && !strcmp(iface_peer, peer)) {
            return true;//port的对端恰好是peer，则返回true
        }
    }
    return false;
}

/* Creates a patch port in bridge 'src' named 'src_name', whose peer is
 * 'dst_name' in bridge 'dst'.  Initializes the patch port's external-ids:'key'
 * to 'key'.
 *
 * If such a patch port already exists, removes it from 'existing_ports'. */
static void
create_patch_port(struct ovsdb_idl_txn *ovs_idl_txn,
                  const char *key, const char *value,
                  const struct ovsrec_bridge *src, const char *src_name,
                  const struct ovsrec_bridge *dst, const char *dst_name,
                  struct shash *existing_ports)
{
    for (size_t i = 0; i < src->n_ports; i++) {
        if (match_patch_port(src->ports[i], dst_name)) {
            /* Patch port already exists on 'src'. */
        	//此桥上有一个接口已连接到dst-name口上，我们将其从existing_port中移除，故
        	//existing_ports中将剩余需要自本机删除的接口（sb中已没有了）
            shash_find_and_delete(existing_ports, src->ports[i]->name);
            return;
        }
    }

    ovsdb_idl_txn_add_comment(ovs_idl_txn,
            "ovn-controller: creating patch port '%s' from '%s' to '%s'",
            src_name, src->name, dst->name);

    struct ovsrec_interface *iface;
    iface = ovsrec_interface_insert(ovs_idl_txn);
    ovsrec_interface_set_name(iface, src_name);
    ovsrec_interface_set_type(iface, "patch");
    const struct smap options = SMAP_CONST1(&options, "peer", dst_name);//设置对端名称
    ovsrec_interface_set_options(iface, &options);

    struct ovsrec_port *port;
    port = ovsrec_port_insert(ovs_idl_txn);
    ovsrec_port_set_name(port, src_name);//设置src_name
    ovsrec_port_set_interfaces(port, &iface, 1);//设置port对应的interface
    const struct smap ids = SMAP_CONST1(&ids, key, value);
    ovsrec_port_set_external_ids(port, &ids);

    struct ovsrec_port **ports;
    ports = xmalloc(sizeof *ports * (src->n_ports + 1));
    memcpy(ports, src->ports, sizeof *ports * src->n_ports);
    ports[src->n_ports] = port;
    ovsrec_bridge_verify_ports(src);
    ovsrec_bridge_set_ports(src, ports, src->n_ports + 1);//桥上口加1

    free(ports);
}

static void
remove_port(const struct ovsrec_bridge_table *bridge_table,
            const struct ovsrec_port *port)
{
    const struct ovsrec_bridge *bridge;

    /* We know the port we want to delete, but we have to find the bridge its
     * on to do so.  Note this only runs on a config change that should be
     * pretty rare. */
    OVSREC_BRIDGE_TABLE_FOR_EACH (bridge, bridge_table) {
        size_t i;
        for (i = 0; i < bridge->n_ports; i++) {
            if (bridge->ports[i] != port) {
                continue;
            }
            struct ovsrec_port **new_ports;
            new_ports = xmemdup(bridge->ports,
                    sizeof *new_ports * (bridge->n_ports - 1));
            if (i != bridge->n_ports - 1) {
                /* Removed port was not last */
                new_ports[i] = bridge->ports[bridge->n_ports - 1];
            }
            ovsrec_bridge_verify_ports(bridge);
            ovsrec_bridge_set_ports(bridge, new_ports, bridge->n_ports - 1);
            free(new_ports);
            ovsrec_port_delete(port);
            return;
        }
    }
}

/* Obtains external-ids:ovn-bridge-mappings from OVSDB and adds patch ports for
 * the local bridge mappings.  Removes any patch ports for bridge mappings that
 * already existed from 'existing_ports'. */
//实现与bridge-mappings桥的连接(br-int 到br-ln)
static void
add_bridge_mappings(struct ovsdb_idl_txn *ovs_idl_txn,
                    const struct ovsrec_bridge_table *bridge_table,
                    const struct ovsrec_open_vswitch_table *ovs_table,
                    const struct sbrec_port_binding_table *port_binding_table,
                    const struct ovsrec_bridge *br_int,
                    struct shash *existing_ports,
                    const struct sbrec_chassis *chassis)
{
    /* Get ovn-bridge-mappings. */
    const char *mappings_cfg = "";
    const struct ovsrec_open_vswitch *cfg;
    cfg = ovsrec_open_vswitch_table_first(ovs_table);
    if (cfg) {
        mappings_cfg = smap_get(&cfg->external_ids, "ovn-bridge-mappings");
        if (!mappings_cfg || !mappings_cfg[0]) {
            return;
        }
    }

    /* Parse bridge mappings. */
    //解析网络与桥的映射关系,保存在bridge_mappings中，key为network,value为ovs_bridge
    struct shash bridge_mappings = SHASH_INITIALIZER(&bridge_mappings);
    char *cur, *next, *start;
    next = start = xstrdup(mappings_cfg);
    while ((cur = strsep(&next, ",")) && *cur) {
        char *network, *bridge = cur;
        const struct ovsrec_bridge *ovs_bridge;

        network = strsep(&bridge, ":");//取出网络名称，桥名称
        if (!bridge || !*network || !*bridge) {
            VLOG_ERR("Invalid ovn-bridge-mappings configuration: '%s'",
                    mappings_cfg);
            break;
        }

        ovs_bridge = get_bridge(bridge_table, bridge);
        if (!ovs_bridge) {
        	//配置指出了此桥，但此桥没有创建，继续
            VLOG_WARN("Bridge '%s' not found for network '%s'",
                    bridge, network);
            continue;
        }

        shash_add(&bridge_mappings, network, ovs_bridge);//记录网络与桥之间的对应关系（key为网络名称，value为桥配置）
    }
    free(start);

    const struct sbrec_port_binding *binding;
    SBREC_PORT_BINDING_TABLE_FOR_EACH (binding, port_binding_table) {
        const char *patch_port_id;
        if (!strcmp(binding->type, "localnet")) {
            patch_port_id = "ovn-localnet-port";
        } else if (!strcmp(binding->type, "l2gateway")) {
            if (!binding->chassis
                || strcmp(chassis->name, binding->chassis->name)) {
                /* This L2 gateway port is not bound to this chassis,
                 * so we should not create any patch ports for it. */
            	//此接口没有绑定到当前chassis上，忽略
                continue;
            }
            patch_port_id = "ovn-l2gateway-port";
        } else {
            /* not a localnet or L2 gateway port. */
        	//其它类型，忽略
            continue;
        }

        //取出此接口的网络名称
        const char *network = smap_get(&binding->options, "network_name");
        if (!network) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
            VLOG_ERR_RL(&rl, "%s port '%s' has no network name.",
                         binding->type, binding->logical_port);
            continue;
        }

        //通过这个网络名称找到对应的桥
        struct ovsrec_bridge *br_ln = shash_find_data(&bridge_mappings, network);
        if (!br_ln) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
            VLOG_ERR_RL(&rl, "bridge not found for %s port '%s' "
                    "with network name '%s'",
                    binding->type, binding->logical_port, network);
            continue;
        }

        //创建两个口，自br-int上连接到br-ln上
        char *name1 = patch_port_name(br_int->name, binding->logical_port);
        char *name2 = patch_port_name(binding->logical_port, br_int->name);
        create_patch_port(ovs_idl_txn, patch_port_id, binding->logical_port,
                          br_int, name1, br_ln, name2, existing_ports);
        create_patch_port(ovs_idl_txn, patch_port_id, binding->logical_port,
                          br_ln, name2, br_int, name1, existing_ports);
        free(name1);
        free(name2);
    }

    shash_destroy(&bridge_mappings);
}

//实现br-int 与br-ln桥之间的接口维护
void
patch_run(struct ovsdb_idl_txn *ovs_idl_txn,
          const struct ovsrec_bridge_table *bridge_table,
          const struct ovsrec_open_vswitch_table *ovs_table,
          const struct ovsrec_port_table *port_table,
          const struct sbrec_port_binding_table *port_binding_table,
          const struct ovsrec_bridge *br_int,
          const struct sbrec_chassis *chassis)
{
    if (!ovs_idl_txn) {
        return;
    }

    /* Figure out what patch ports already exist.
     *
     * ovn-controller does not create or use ports of type "ovn-l3gateway-port"
     * or "ovn-logical-patch-port", but older version did.  We still recognize
     * them here, so that we delete them at the end of this function, to avoid
     * leaving useless ports on upgrade. */
    struct shash existing_ports = SHASH_INITIALIZER(&existing_ports);
    const struct ovsrec_port *port;
    OVSREC_PORT_TABLE_FOR_EACH (port, port_table) {
        if (smap_get(&port->external_ids, "ovn-localnet-port")//这种类型，实现localnet
            || smap_get(&port->external_ids, "ovn-l2gateway-port")//这种类型，实现l2gateway
            || smap_get(&port->external_ids, "ovn-l3gateway-port")
            || smap_get(&port->external_ids, "ovn-logical-patch-port")) {
            shash_add(&existing_ports, port->name, port);//ovn支持的口全部收集起来
        }
    }

    /* Create in the database any patch ports that should exist.  Remove from
     * 'existing_ports' any patch ports that do exist in the database and
     * should be there. */
    //两种类型（1。ovn-localnet-port 2. ovn-l2gateway-port)
    //实现br-int与br-ln之间的连接
    add_bridge_mappings(ovs_idl_txn, bridge_table, ovs_table,
                        port_binding_table, br_int, &existing_ports, chassis);

    /* Now 'existing_ports' only still contains patch ports that exist in the
     * database but shouldn't.  Delete them from the database. */
    //仍存在于existing_ports中的接口是在数据库中已不存在的数，需要将其自br-int中移除
    struct shash_node *port_node, *port_next_node;
    SHASH_FOR_EACH_SAFE (port_node, port_next_node, &existing_ports) {
        port = port_node->data;
        shash_delete(&existing_ports, port_node);
	//移除掉已存在的桥
        remove_port(bridge_table, port);
    }
    shash_destroy(&existing_ports);
}
