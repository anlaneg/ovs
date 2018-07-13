/* Copyright (c) 2015, 2016 Nicira, Inc.
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
#include <unistd.h>

#include "chassis.h"

#include "lib/smap.h"
#include "lib/vswitch-idl.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/vlog.h"
#include "ovn/lib/chassis-index.h"
#include "ovn/lib/ovn-sb-idl.h"
#include "ovn-controller.h"
#include "lib/util.h"

VLOG_DEFINE_THIS_MODULE(chassis);

#ifndef HOST_NAME_MAX
/* For windows. */
#define HOST_NAME_MAX 255
#endif /* HOST_NAME_MAX */

void
chassis_register_ovs_idl(struct ovsdb_idl *ovs_idl)
{
    ovsdb_idl_add_table(ovs_idl, &ovsrec_table_open_vswitch);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_open_vswitch_col_external_ids);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_open_vswitch_col_iface_types);
    ovsdb_idl_add_table(ovs_idl, &ovsrec_table_bridge);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_bridge_col_datapath_type);
}

static const char *
pop_tunnel_name(uint32_t *type)
{
    if (*type & GENEVE) {
        *type &= ~GENEVE;
        return "geneve";
    } else if (*type & STT) {
        *type &= ~STT;
        return "stt";
    } else if (*type & VXLAN) {
        *type &= ~VXLAN;
        return "vxlan";
    }

    OVS_NOT_REACHED();
}

//取物理网络与ovs桥之间的映射关系
static const char *
get_bridge_mappings(const struct smap *ext_ids)
{
    return smap_get_def(ext_ids, "ovn-bridge-mappings", "");
}

static const char *
get_cms_options(const struct smap *ext_ids)
{
    return smap_get_def(ext_ids, "ovn-cms-options", "");
}

/* Returns this chassis's Chassis record, if it is available and is currently
 * amenable to a transaction. */
const struct sbrec_chassis *
chassis_run(struct ovsdb_idl_txn *ovnsb_idl_txn,
            struct ovsdb_idl_index *sbrec_chassis_by_name,
            const struct ovsrec_open_vswitch_table *ovs_table,
            const char *chassis_id,
            const struct ovsrec_bridge *br_int)
{
    if (!ovnsb_idl_txn) {
        return NULL;//无南向连接，不处理
    }

    const struct ovsrec_open_vswitch *cfg;
    const char *encap_type, *encap_ip;
    static bool inited = false;

    //查本机配置
    cfg = ovsrec_open_vswitch_table_first(ovs_table);
    if (!cfg) {
        VLOG_INFO("No Open_vSwitch row defined.");
        return NULL;
    }

    //取出本机关于ovn封装协议，及封装ip的配置
    //ovn-encap-type用于指出一个chassis连接到另一个时采用的封装协议。
    //encap_type可能指定多个,每个之间采用','号进行分割。每种encap_type需要对应一个ovn-encap-ip,即
    //向对端发送报文时，自已的ip
    encap_type = smap_get(&cfg->external_ids, "ovn-encap-type");
    encap_ip = smap_get(&cfg->external_ids, "ovn-encap-ip");
    if (!encap_type || !encap_ip) {
        VLOG_INFO("Need to specify an encap type and ip");
        return NULL;
    }

    //开始解析封装用的隧道类型
    char *tokstr = xstrdup(encap_type);
    char *save_ptr = NULL;
    char *token;
    uint32_t req_tunnels = 0;
    for (token = strtok_r(tokstr, ",", &save_ptr); token != NULL;
         token = strtok_r(NULL, ",", &save_ptr)) {
        uint32_t type = get_tunnel_type(token);
        if (!type) {
            VLOG_INFO("Unknown tunnel type: %s", token);
        }
        req_tunnels |= type;//容许设置多种封装方式
    }
    free(tokstr);

    //在配置中取当前主机的名称配置
    const char *hostname = smap_get_def(&cfg->external_ids, "hostname", "");
    char hostname_[HOST_NAME_MAX + 1];
    if (!hostname[0]) {
    	//如果没有配置，则说明第一次配置，取主机名称
        if (gethostname(hostname_, sizeof hostname_)) {
            hostname_[0] = '\0';
        }
        hostname = hostname_;
    }

    //取当前物理网络与ovs桥之间的映射配置
    const char *bridge_mappings = get_bridge_mappings(&cfg->external_ids);
    const char *datapath_type =
        br_int && br_int->datapath_type ? br_int->datapath_type : "";//br-int的datapath类型
    const char *cms_options = get_cms_options(&cfg->external_ids);

    //取接口类型配置
    struct ds iface_types = DS_EMPTY_INITIALIZER;
    ds_put_cstr(&iface_types, "");
    for (int j = 0; j < cfg->n_iface_types; j++) {
        ds_put_format(&iface_types, "%s,", cfg->iface_types[j]);
    }
    ds_chomp(&iface_types, ',');
    const char *iface_types_str = ds_cstr(&iface_types);//所有接口类型

    //向sb库检查是否包含本chassis的配置
    const struct sbrec_chassis *chassis_rec
        = chassis_lookup_by_name(sbrec_chassis_by_name, chassis_id);
    //ovn-encap-csum用于指出是否将encap的checksum下沉到网卡来做（true为不下沉，false为下沉）
    const char *encap_csum = smap_get_def(&cfg->external_ids,
                                          "ovn-encap-csum", "true");
    if (chassis_rec) {
    	//sb库中有本chassis的配置
        if (strcmp(hostname, chassis_rec->hostname)) {
        	//hostname发生变更，更新hostname
            sbrec_chassis_set_hostname(chassis_rec, hostname);
        }

        /* Determine new values for Chassis external-ids. */
        const char *chassis_bridge_mappings
            = get_bridge_mappings(&chassis_rec->external_ids);
        const char *chassis_datapath_type
            = smap_get_def(&chassis_rec->external_ids, "datapath-type", "");
        const char *chassis_iface_types
            = smap_get_def(&chassis_rec->external_ids, "iface-types", "");
        const char *chassis_cms_options
            = get_cms_options(&chassis_rec->external_ids);

        /* If any of the external-ids should change, update them. */
        //bridge_mappings,chassis_datapath_type,chassis_iface_types任意一个发生变更
        //则更新这些配置项
        if (strcmp(bridge_mappings, chassis_bridge_mappings) ||
            strcmp(datapath_type, chassis_datapath_type) ||
            strcmp(iface_types_str, chassis_iface_types) ||
            strcmp(cms_options, chassis_cms_options)) {
            struct smap new_ids;
            smap_clone(&new_ids, &chassis_rec->external_ids);
            smap_replace(&new_ids, "ovn-bridge-mappings", bridge_mappings);
            smap_replace(&new_ids, "datapath-type", datapath_type);
            smap_replace(&new_ids, "iface-types", iface_types_str);
            smap_replace(&new_ids, "ovn-cms-options", cms_options);
            sbrec_chassis_verify_external_ids(chassis_rec);
            sbrec_chassis_set_external_ids(chassis_rec, &new_ids);//更新external_ids
            smap_destroy(&new_ids);
        }

        /* Compare desired tunnels against those currently in the database. */
        uint32_t cur_tunnels = 0;
        bool same = true;
        for (int i = 0; i < chassis_rec->n_encaps; i++) {
            cur_tunnels |= get_tunnel_type(chassis_rec->encaps[i]->type);
            same = same && !strcmp(chassis_rec->encaps[i]->ip, encap_ip);

            same = same && !strcmp(
                smap_get_def(&chassis_rec->encaps[i]->options, "csum", ""),
                encap_csum);
        }

        same = same && req_tunnels == cur_tunnels;//这句话的意义？（无意义代码）

        if (same) {
        	//无变更
            /* Nothing changed. */
            inited = true;
            ds_destroy(&iface_types);
            return chassis_rec;
        } else if (!inited) {
        	//如果是第一次走到这里，打log
            struct ds cur_encaps = DS_EMPTY_INITIALIZER;
            for (int i = 0; i < chassis_rec->n_encaps; i++) {
                ds_put_format(&cur_encaps, "%s,",
                              chassis_rec->encaps[i]->type);
            }
            ds_chomp(&cur_encaps, ',');

            VLOG_WARN("Chassis config changing on startup, make sure "
                      "multiple chassis are not configured : %s/%s->%s/%s",
                      ds_cstr(&cur_encaps),
                      chassis_rec->encaps[0]->ip,
                      encap_type, encap_ip);
            ds_destroy(&cur_encaps);
        }
    }

    //向南向库中注册本chassis
    ovsdb_idl_txn_add_comment(ovnsb_idl_txn,
                              "ovn-controller: registering chassis '%s'",
                              chassis_id);

    if (!chassis_rec) {
    	//没有这个chassis,创建，并添加相应的配置项
        struct smap ext_ids = SMAP_INITIALIZER(&ext_ids);
        smap_add(&ext_ids, "ovn-bridge-mappings", bridge_mappings);
        smap_add(&ext_ids, "datapath-type", datapath_type);
        smap_add(&ext_ids, "iface-types", iface_types_str);
        chassis_rec = sbrec_chassis_insert(ovnsb_idl_txn);//向南向库中加入chassis_rec(相当于注册agent)
        sbrec_chassis_set_name(chassis_rec, chassis_id);
        sbrec_chassis_set_hostname(chassis_rec, hostname);
        sbrec_chassis_set_external_ids(chassis_rec, &ext_ids);
        smap_destroy(&ext_ids);
    }

    ds_destroy(&iface_types);
    int n_encaps = count_1bits(req_tunnels);//有多少种封装方式
    struct sbrec_encap **encaps = xmalloc(n_encaps * sizeof *encaps);
    const struct smap options = SMAP_CONST1(&options, "csum", encap_csum);
    for (int i = 0; i < n_encaps; i++) {
        const char *type = pop_tunnel_name(&req_tunnels);

        encaps[i] = sbrec_encap_insert(ovnsb_idl_txn);

        sbrec_encap_set_type(encaps[i], type);//不同的封装
        sbrec_encap_set_ip(encaps[i], encap_ip);
        sbrec_encap_set_options(encaps[i], &options);
        sbrec_encap_set_chassis_name(encaps[i], chassis_id);
    }
    sbrec_chassis_set_encaps(chassis_rec, encaps, n_encaps);
    free(encaps);

    inited = true;
    return chassis_rec;
}

/* Returns true if the database is all cleaned up, false if more work is
 * required. */
bool
chassis_cleanup(struct ovsdb_idl_txn *ovnsb_idl_txn,
                const struct sbrec_chassis *chassis_rec)
{
    if (!chassis_rec) {
        return true;
    }
    if (ovnsb_idl_txn) {
        ovsdb_idl_txn_add_comment(ovnsb_idl_txn,
                                  "ovn-controller: unregistering chassis '%s'",
                                  chassis_rec->name);
        sbrec_chassis_delete(chassis_rec);
    }
    return false;
}
