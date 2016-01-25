/*
 * (c) Copyright 2015 Hewlett Packard Enterprise Development LP
 * Copyright (c) 2009, 2010, 2011, 2012, 2013, 2014 Nicira, Inc.
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
 *
 */

#include <errno.h>

#include "config.h"
#include "ofproto/ofproto-provider.h"
#include "ofproto/bond.h"
#include "ofproto/tunnel.h"
#include "bundle.h"
#include "coverage.h"
#include "netdev.h"
#include "smap.h"
#include "timer.h"
#include "seq.h"
#include "unaligned.h"
#include "vlan-bitmap.h"
#include "openvswitch/vlog.h"
#include "ofproto-sim-provider.h"
#include "vswitch-idl.h"

#include "netdev-sim.h"

VLOG_DEFINE_THIS_MODULE(P4_ofproto_provider_sim);

#define MAX_CMD_LEN             2048
#define SWNS_EXEC               "/sbin/ip netns exec swns"

#if 1 // XXX find where it comes from
#define VLAN_BITMAP_SIZE    4096
#endif

static struct sim_provider_ofport *
sim_provider_ofport_cast(const struct ofport *ofport)
{
    return ofport ?
        CONTAINER_OF(ofport, struct sim_provider_ofport, up) : NULL;
}

static struct sim_provider_ofport *
sim_provider_bundle_ofport_cast(const struct ovs_list *lnode)
{
    return lnode ?
        CONTAINER_OF(lnode, struct sim_provider_ofport, bundle_node) : NULL;
}


static inline struct sim_provider_node *
sim_provider_node_cast(const struct ofproto *ofproto)
{
    ovs_assert(ofproto->ofproto_class == &ofproto_sim_provider_class);

    return CONTAINER_OF(ofproto, struct sim_provider_node, up);
}

/* All existing ofproto provider instances, indexed by ->up.name. */
static struct hmap all_sim_provider_nodes =
HMAP_INITIALIZER(&all_sim_provider_nodes);

/* Factory functions. */

static void
init(const struct shash *iface_hints)
{
    return;
}

static void
enumerate_types(struct sset *types)
{
    struct sim_provider_node *ofproto;

    sset_add(types, "system");
    sset_add(types, "vrf");
}

static int
enumerate_names(const char *type, struct sset *names)
{
    struct sim_provider_node *ofproto;
    const char *port_type;

    // XXX documentation says caller has already cleared the names..
    // should not do it here ?
    // update name for types supported ("system" and "vrf")
    sset_clear(names);
    HMAP_FOR_EACH(ofproto, all_sim_provider_node, &all_sim_provider_nodes) {
        if (strcmp(type, ofproto->up.type)) {
            continue;
        }

        sset_add(names, ofproto->up.name);
    }

    return 0;
}

static int
del(const char *type OVS_UNUSED, const char *name OVS_UNUSED)
{
    return 0;
}

static const char *
port_open_type(const char *datapath_type OVS_UNUSED, const char *port_type)
{
    // XXX: comments indicate that for userspace DP (such as bmv2) type could be
    // reported as "tap"
    if (port_type && (strcmp(port_type, OVSREC_INTERFACE_TYPE_INTERNAL) == 0)) {
        return port_type;
    }
    return "system";
}

/* Basic life-cycle. */

static struct ofproto *
alloc(void)
{
    struct sim_provider_node *ofproto = xzalloc(sizeof *ofproto);

    return &ofproto->up;
}

static void
dealloc(struct ofproto *ofproto_)
{
    struct sim_provider_node *ofproto = sim_provider_node_cast(ofproto_);

    free(ofproto);
}

static int
construct(struct ofproto *ofproto_)
{
    struct sim_provider_node *ofproto = sim_provider_node_cast(ofproto_);
    struct shash_node *node, *next;
    int error = 0;

    VLOG_INFO("P4:Ofproto->construct - name %s type %s",
                ofproto->up.name, ofproto->up.type);
#if 0
    char cmd_str[MAX_CMD_LEN];

    /* If the ofproto is of type BRIDGE, then create a bridge with the same
     * name in ASIC OVS. In ASIC OVS creating a bridge also creates a bundle &
     * port with the same name. The port will be 'internal' type. */
    if (strcmp(ofproto_->type, "system") == 0) {

        snprintf(cmd_str, MAX_CMD_LEN, "%s --may-exist add-br %s",
                 OVS_VSCTL, ofproto->up.name);
        if (system(cmd_str) != 0) {
            VLOG_ERR("Failed to add bridge in ASIC OVS. cmd=%s, rc=%s",
                     cmd_str, strerror(errno));
            error = 1;
        }

        snprintf(cmd_str, MAX_CMD_LEN, "%s set br %s datapath_type=netdev",
                 OVS_VSCTL, ofproto->up.name);
        if (system(cmd_str) != 0) {
            VLOG_ERR("Failed to set bridge datapath_type. cmd=%s, rc=%s",
                     cmd_str, strerror(errno));
            error = 1;
        }

        snprintf(cmd_str, MAX_CMD_LEN, "%s set port %s trunks=0",
                 OVS_VSCTL, ofproto->up.name);
        if (system(cmd_str) != 0) {
            VLOG_ERR
                ("Failed to set trunks in the bridge bundle. cmd=%s, rc=%s",
                 cmd_str, strerror(errno));
            error = 1;
        }

        snprintf(cmd_str, MAX_CMD_LEN, "%s /sbin/ip link set dev %s up",
                 SWNS_EXEC, ofproto->up.name);
        if (system(cmd_str) != 0) {
            VLOG_ERR("Failed to set link state. cmd=%s, rc=%s", cmd_str,
                     strerror(errno));
            error = 1;
        }
        ofproto->vrf = false;

    } else {
        ofproto->vrf = true;
    }
#endif

    ofproto->netflow = NULL;
    ofproto->stp = NULL;
    ofproto->rstp = NULL;
    ofproto->dump_seq = 0;
    hmap_init(&ofproto->bundles);
    hmap_init(&ofproto->vlans);
    ofproto->ms = NULL;
    ofproto->has_bonded_bundles = false;
    ofproto->lacp_enabled = false;
    ofproto_tunnel_init();
    ovs_mutex_init_adaptive(&ofproto->stats_mutex);
    ovs_mutex_init(&ofproto->vsp_mutex);

    guarded_list_init(&ofproto->pins);

    sset_init(&ofproto->ports);
    sset_init(&ofproto->ghost_ports);
    sset_init(&ofproto->port_poll_set);
    ofproto->port_poll_errno = 0;
    ofproto->change_seq = 0;
    ofproto->pins_seq = seq_create();
    ofproto->pins_seqno = seq_read(ofproto->pins_seq);

    hmap_insert(&all_sim_provider_nodes, &ofproto->all_sim_provider_node,
                hash_string(ofproto->up.name, 0));

    memset(&ofproto->stats, 0, sizeof ofproto->stats);
    ofproto->vlans_bmp = bitmap_allocate(VLAN_BITMAP_SIZE);
    ofproto->vlan_intf_bmp = bitmap_allocate(VLAN_BITMAP_SIZE);
    ofproto_init_tables(ofproto_, N_TABLES);
    ofproto->up.tables[TBL_INTERNAL].flags = OFTABLE_HIDDEN | OFTABLE_READONLY;

#if 1
    ofproto_init_max_ports(ofproto_, MAX_P4_SWITCH_PORTS);
#endif

    return error;
}

static void
destruct(struct ofproto *ofproto_ OVS_UNUSED)
{
    struct sim_provider_node *ofproto = sim_provider_node_cast(ofproto_);
    char ovs_delbr[80];

    if (ofproto->vrf == false) {

        sprintf(ovs_delbr, "%s del-br %s", OVS_VSCTL, ofproto->up.name);
        if (system(ovs_delbr) != 0) {
            VLOG_ERR("Failed to delete the bridge. cmd=%s, rc=%s",
                     ovs_delbr, strerror(errno));
        }
    }

    hmap_remove(&all_sim_provider_nodes, &ofproto->all_sim_provider_node);

    hmap_destroy(&ofproto->bundles);
    hmap_destroy(&ofproto->vlans);

    sset_destroy(&ofproto->ports);
    sset_destroy(&ofproto->ghost_ports);
    sset_destroy(&ofproto->port_poll_set);

    ovs_mutex_destroy(&ofproto->stats_mutex);
    ovs_mutex_destroy(&ofproto->vsp_mutex);

    return;
}

static int
run(struct ofproto *ofproto_ OVS_UNUSED)
{
    return 0;
}

static void
wait(struct ofproto *ofproto_ OVS_UNUSED)
{
    return;
}

static void
query_tables(struct ofproto *ofproto,
             struct ofputil_table_features *features,
             struct ofputil_table_stats *stats)
{
    return;
}

static struct ofport *
port_alloc(void)
{
    struct sim_provider_ofport *port = xzalloc(sizeof *port);

    return &port->up;
}

static void
port_dealloc(struct ofport *port_)
{
    struct sim_provider_ofport *port = sim_provider_ofport_cast(port_);

    free(port);
}

static int
port_construct(struct ofport *port_)
{
    struct sim_provider_ofport *port = sim_provider_ofport_cast(port_);

    // XXX clean-up the provider_ofport structure - add the info as needed
    VLOG_INFO("port_construct");
    return 0;
}

static void
port_destruct(struct ofport *port_ OVS_UNUSED)
{
    return;
}

static void
port_reconfigured(struct ofport *port_, enum ofputil_port_config old_config)
{
    // XXX old_config is a bitmap (set of flags like down, no_rx....)
    return;
}

static bool
cfm_status_changed(struct ofport *ofport_)
{
    return false;
}

static bool
bfd_status_changed(struct ofport *ofport_ OVS_UNUSED)
{
    return false;
}

static struct ofbundle *
bundle_lookup(const struct sim_provider_node *ofproto, void *aux)
{
    struct ofbundle *bundle;

    HMAP_FOR_EACH_IN_BUCKET(bundle, hmap_node, hash_pointer(aux, 0),
                            &ofproto->bundles) {
        if (bundle->aux == aux) {
            return bundle;
        }
    }
    return NULL;
}

static struct ofp4vlan *
p4vlan_lookup(const struct sim_provider_node *ofproto, uint32_t vid)
{
    struct ofp4vlan *p4vlan;
    // XXX: what is basis - initial value? use -1
    HMAP_FOR_EACH_IN_BUCKET(p4vlan, hmap_node, hash_int(vid, 0),
                            &ofproto->vlans) {
        if (p4vlan->vid == vid) {
            return p4vlan;
        }
    }
    return NULL;
}

static void
enable_port_in_iptables(const char *port_name)
{
#if 0
    char cmd[MAX_CMD_LEN];

    snprintf(cmd, MAX_CMD_LEN, "%s iptables -D INPUT -i %s -j DROP",
             SWNS_EXEC, port_name);
    if (system(cmd) != 0) {
        VLOG_ERR("Failed to delete DROP rule. cmd=%s rc=%s", cmd,
                 strerror(errno));
    }

    snprintf(cmd, MAX_CMD_LEN, "%s iptables -D FORWARD -i %s -j DROP",
             SWNS_EXEC, port_name);
    if (system(cmd) != 0) {
        VLOG_ERR("Failed to delete DROP rule. cmd=%s rc=%s", cmd,
                 strerror(errno));
    }
#endif
}

static void
disable_port_in_iptables(const char *port_name)
{
#if 0
    int rc = 0;
    char cmd[MAX_CMD_LEN];

    /* Do not add drop rules if the "Check" command returns success. */
    snprintf(cmd, MAX_CMD_LEN, "%s iptables -C INPUT -i %s -j DROP",
             SWNS_EXEC, port_name);
    rc = system(cmd);
    if (rc != 0) {

        snprintf(cmd, MAX_CMD_LEN, "%s iptables -A INPUT -i %s -j DROP",
                 SWNS_EXEC, port_name);
        if (system(cmd) != 0) {
            VLOG_ERR("Failed to add DROP rules: cmd=%s rc=%s", cmd,
                     strerror(errno));
        }

        snprintf(cmd, MAX_CMD_LEN, "%s iptables -A FORWARD -i %s -j DROP",
                 SWNS_EXEC, port_name);
        if (system(cmd) != 0) {
            VLOG_ERR("Failed to add DROP rules: cmd=%s rc=%s", cmd,
                     strerror(errno));
        }
    }
#endif
}

static void
bundle_del_port(struct sim_provider_ofport *port)
{
    struct ofbundle *bundle = port->bundle;

    list_remove(&port->bundle_node);
    port->bundle = NULL;

    /* Enable the port in IP tables. So that regular L3 traffic can flow
     * across it. */
    if (port->iptable_rules_added == true) {
        enable_port_in_iptables(netdev_get_name(port->up.netdev));
        port->iptable_rules_added = false;
    }
}

static bool
bundle_add_port(struct ofbundle *bundle, ofp_port_t ofp_port)
{
#if 1
    struct sim_provider_ofport *port;

    port = get_ofp_port(bundle->ofproto, ofp_port);
    if (!port) {
        return false;
    }

    if (port->bundle != bundle) {
        if (port->bundle) {
            bundle_remove(&port->up);
        }

        port->bundle = bundle;
        list_push_back(&bundle->ports, &port->bundle_node);
    }
#endif

    return true;
}

static void
sim_bridge_vlan_routing_update(struct sim_provider_node *ofproto, int vlan,
                               bool add)
{
#if 0
    int i = 0, n = 0;
    int vlan_count = 0;
    char cmd_str[MAX_CMD_LEN];

    if (add) {

        /* If the vlan is already added to the list. */
        if (bitmap_is_set(ofproto->vlan_intf_bmp, vlan)) {
            return;
        }

        /* Save the VLAN routing interface IDs. */
        bitmap_set1(ofproto->vlan_intf_bmp, vlan);

    } else {

        /* If the vlan is already unset in the list. */
        if (!bitmap_is_set(ofproto->vlan_intf_bmp, vlan)) {
            return;
        }

        /* Unset the VLAN routing interface IDs. */
        bitmap_set0(ofproto->vlan_intf_bmp, vlan);
    }

    n = snprintf(cmd_str, MAX_CMD_LEN, "%s set port %s ", OVS_VSCTL,
                 ofproto->up.name);

    for (i = 1; i < 4095; i++) {

        if (bitmap_is_set(ofproto->vlan_intf_bmp, i)) {

            if (vlan_count == 0) {
                n += snprintf(&cmd_str[n], (MAX_CMD_LEN - n), " trunks=%d", i);
            } else {
                n += snprintf(&cmd_str[n], (MAX_CMD_LEN - n), ",%d", i);
            }
            ovs_assert(n <= MAX_CMD_LEN);

            vlan_count += 1;
        }
    }

    if (vlan_count == 0) {
        n += snprintf(&cmd_str[n], (MAX_CMD_LEN - n), " trunks=0");
    }

    if (system(cmd_str) != 0) {
        VLOG_ERR("Failed to modify bridge interface trunks: cmd=%s, rc=%s",
                 cmd_str, strerror(errno));
    }
#endif
}

/* Freeing up bundle and its members on heap */
static void
bundle_destroy(struct ofbundle *bundle)
{
#if 0
    struct sim_provider_node *ofproto = NULL;
    struct sim_provider_ofport *port = NULL, *next_port = NULL;
    const char *type = NULL;
    char cmd_str[MAX_CMD_LEN];

    if (!bundle) {
        return;
    }

    ofproto = bundle->ofproto;

    if (bundle->is_added_to_sim_ovs == true) {
        snprintf(cmd_str, MAX_CMD_LEN, "%s del-port %s", OVS_VSCTL,
                 bundle->name);
        if (system(cmd_str) != 0) {
            VLOG_ERR("Failed to delete the existing port. cmd=%s, rc=%s",
                     cmd_str, strerror(errno));
        }
        bundle->is_added_to_sim_ovs = false;
    }

    /* If the ofproto is of type System/Bridge, and VLAN routing is enabled on
     * this bundle then delete that VLAN ID from BRIDGE interface created in
     * ASIC OVS. We should ignore the bundle whose name is same as the BRIDGE
     * name. */
    if (bundle->is_vlan_routing_enabled == true) {
        sim_bridge_vlan_routing_update(ofproto, bundle->vlan, false);
        bundle->is_vlan_routing_enabled = false;
    }

    LIST_FOR_EACH_SAFE(port, next_port, bundle_node, &bundle->ports) {
        bundle_del_port(port);
    }

    hmap_remove(&ofproto->bundles, &bundle->hmap_node);

    if (bundle->name) {
        free(bundle->name);
    }
    if (bundle->trunks) {
        free(bundle->trunks);
    }

    free(bundle);
#endif
}

static void
vlan_mode_to_port_type(int32_t vlan_mode, int32_t *port_type, int32_t *tag_mode)
{
    ovs_assert(port_type && tag_mode);
    *port_type = SWITCH_API_INTERFACE_L2_VLAN_TRUNK;
    *tag_mode =  SWITCH_VLAN_PORT_UNTAGGED; // XXX support other types
    if (vlan_mode == PORT_VLAN_ACCESS) {
        *port_type = SWITCH_API_INTERFACE_L2_VLAN_ACCESS;
        *tag_mode = SWITCH_VLAN_PORT_UNTAGGED;
    } else if (vlan_mode == PORT_VLAN_TRUNK) {
        // XXX
    } else if (vlan_mode == PORT_VLAN_NATIVE_TAGGED) {
        // XXX
    } else if (vlan_mode == PORT_VLAN_NATIVE_UNTAGGED) {
        // XXX
    } else {
        *port_type = SWITCH_API_INTERFACE_NONE;
    }
    return;
}

#define P4_HANDLE_IS_VALID(_h) ((_h) != SWITCH_API_INVALID_HANDLE)
static void
p4_switch_vlan_port_create (struct ofbundle *bundle, int32_t vlan)
{
    struct ofp4vlan *p4vlan;
    struct sim_provider_node *ofproto = bundle->ofproto;

    p4vlan = p4vlan_lookup(ofproto, vlan);
    if (p4vlan && bundle->port_lag_handle) {
        switch_vlan_port_t vlan_port;

        vlan_port.handle = bundle->port_lag_handle;
        vlan_port.tagging_mode = bundle->tag_mode; // XXX: does it matter for remove?
        VLOG_INFO("switch_api_vlan_ports_add - vlan 0x%x, port hdl 0x%x",
                    p4vlan->vlan_handle, vlan_port.handle);
        switch_api_vlan_ports_add(0, p4vlan->vlan_handle, 1, &vlan_port);
    }
    return;
}

static void
p4_switch_vlan_port_delete (struct ofbundle *bundle, int32_t vlan)
{
    struct ofp4vlan *p4vlan;
    struct sim_provider_node *ofproto = bundle->ofproto;

    p4vlan = p4vlan_lookup(ofproto, vlan);
    if (p4vlan && bundle->port_lag_handle) {
        switch_vlan_port_t vlan_port;

        vlan_port.handle = bundle->port_lag_handle;
        vlan_port.tagging_mode = bundle->tag_mode; // XXX: does it matter for remove?
        VLOG_INFO("switch_api_vlan_ports_remove - vlan 0x%x, port hdl 0x%x",
                    p4vlan->vlan_handle, vlan_port.handle);
        switch_api_vlan_ports_remove(0, p4vlan->vlan_handle, 1, &vlan_port);
    }
    return;
}

static void
p4_switch_interface_create (struct ofbundle *bundle)
{
    switch_api_interface_info_t i_info;
    struct sim_provider_ofport *port = NULL;
    int32_t device = 0;

    // XXX use if_handle valid function from switchapi if available
    ovs_assert(!P4_HANDLE_IS_VALID(bundle->if_handle));
    memset(&i_info, 0, sizeof(switch_api_interface_info_t));

    port = sim_provider_bundle_ofport_cast(list_front(&bundle->ports));

    if (bundle->is_lag) {
        // XXX LAG not supported
        return;
    }
    netdev_get_device_port_handle(port->up.netdev, &device,
                                    &bundle->port_lag_handle);
    i_info.type = bundle->port_type;
    i_info.u.port_lag_handle = bundle->port_lag_handle;
    VLOG_INFO("switch_api_interface_create - type %d, port_handle 0x%x",
                i_info.type, i_info.u.port_lag_handle);

    bundle->if_handle = switch_api_interface_create(device, &i_info);
    if (bundle->if_handle == SWITCH_API_INVALID_HANDLE) {
        VLOG_ERR("switch_api_interface_create - failed");
    }
    VLOG_INFO("switch_api_interface_create - if_handle 0x%x",
                bundle->if_handle);
    return;
}

static void
p4_switch_interface_delete (struct ofbundle *bundle)
{
    if (!P4_HANDLE_IS_VALID(bundle->if_handle)) {
        // No interface is created in P4 so far
        return;
    }
    if (bundle->port_type == SWITCH_API_INTERFACE_L2_VLAN_ACCESS) {
        if (bundle->vlan != -1) {
            p4_switch_vlan_port_delete(bundle, bundle->vlan);
        }
        VLOG_INFO("switch_api_interface_delete(access) - if_handle 0x%x",
                    bundle->if_handle);
        switch_api_interface_delete(0, bundle->if_handle);
        return;
    }
    if (bundle->port_type == SWITCH_API_INTERFACE_L2_VLAN_TRUNK) {
        int b;
        if (bundle->trunks) {
            // Delete pv mappings for all trunk vlans
            for (b=0; b<VLAN_BITMAP_SIZE; b++) {
                if (bitmap_is_set(bundle->trunks, b)) {
                    p4_switch_vlan_port_delete(bundle, b);
                }
            }
            free(bundle->trunks);
            bundle->trunks = NULL;
        }
        VLOG_INFO("switch_api_interface_delete (trunk) - if_handle 0x%x",
                    bundle->if_handle);
        switch_api_interface_delete(0, bundle->if_handle);
        bundle->if_handle = SWITCH_API_INVALID_HANDLE;
        return;
    }
    return;
}

#if 0
static int
bundle_configure (struct ofbundle *bundle)
{
    struct sim_provider_node *ofproto = bundle->ofproto;
    int32_t n_members;
    struct sim_provider_ofport *port = NULL;
    switch_api_interface_info_t i_info;
    int device = 0;
    struct ofp4vlan *p4vlan;
    switch_vlan_port_t vlan_port;
    switch_vlan_tagging_mode_t tagging_mode;
    int ret_val = 0;
    switch_handle_t vlan_handle = SWITCH_API_INVALID_HANDLE;

    n_members = list_size(&bundle->ports);

    if (n_members == 1) {
        if (bundle->is_lag) {
            // XXX: delete lag from p4
        }
        bundle->is_lag = false;
        port = sim_provider_bundle_ofport_cast(list_front(&bundle->ports));
        netdev_get_device_port_handle(port->up.netdev, &device,
                                        &bundle->port_lag_handle);

    } else {
        // create switchapi lag port and add member ports to it
        // ...
    }
    // common code to create switchapi_interface for port or lag
    memset(&i_info, 0, sizeof(switch_api_interface_info_t));

    i_info.type = SWITCH_API_INTERFACE_L2_VLAN_TRUNK;
    tagging_mode = SWITCH_VLAN_PORT_UNTAGGED;

#if 1
    if (bundle->vlan_mode == PORT_VLAN_ACCESS) {
        i_info.type = SWITCH_API_INTERFACE_L2_VLAN_ACCESS;
        tagging_mode = SWITCH_VLAN_PORT_UNTAGGED;
    } else if (bundle->vlan_mode == PORT_VLAN_TRUNK) {
        // XXX
    } else if (bundle->vlan_mode == PORT_VLAN_NATIVE_TAGGED) {
        // XXX
    } else if (bundle->vlan_mode == PORT_VLAN_NATIVE_UNTAGGED) {
        // XXX
    } else {
        ovs_assert(0);
    }
#endif
    i_info.u.port_lag_handle = bundle->port_lag_handle;
    VLOG_INFO("switch_api_interface_create - type %d, tagging %d, handle %d",
                i_info.type, tagging_mode, i_info.u.port_lag_handle);

    bundle->if_handle = switch_api_interface_create(device, &i_info);
    if (bundle->if_handle == SWITCH_API_INVALID_HANDLE) {
        ret_val = EINVAL; // XXX where are correct error codes?
        VLOG_ERR("switch_api_interface_create - failed");
        goto err_ret;
    }
    VLOG_INFO("switch_api_interface_create - handle 0x%x", bundle->if_handle);
    if (bundle->vlan > 0) {
        // valid vlan - check if vlan is already created
        p4vlan = p4vlan_lookup(ofproto, (uint32_t)bundle->vlan);
        if (p4vlan) {
            vlan_handle = p4vlan->vlan_handle;
        } else {
            // XXX should we assert if this is not allowed by ovs
            vlan_handle = SWITCH_API_INVALID_HANDLE;
            VLOG_ERR("vlan %d, not created", bundle->vlan);
        }
    }
    if (vlan_handle != SWITCH_API_INVALID_HANDLE) {
        vlan_port.handle = bundle->port_lag_handle;
        vlan_port.tagging_mode = tagging_mode;
        VLOG_INFO("switch_api_vlan_ports_add - vlan 0x%x, port hdl 0x%x",
                    vlan_handle, vlan_port.handle);
        ret_val = switch_api_vlan_ports_add(device, vlan_handle, 1, &vlan_port);
        if (ret_val) {
            VLOG_ERR("switch_api_vlan_ports_add - failed");
            goto err_ret;
        }
    }
    if (bundle->vlan_mode != PORT_VLAN_ACCESS) {
        // XXX got thru' trunks bitmap and create all the vlan_ports
    }

#if 0
    struct sim_provider_ofport *port = NULL, *next_port = NULL;
    char cmd_str[MAX_CMD_LEN];
    int i = 0, n = 0, n_ports = 0;
    uint32_t vlan_count = 0;

    // XXX handle internal interfaces
    // If num_members == 1 create port handle
    /* If this bundle is already added in the ASIC simulator OVS then delete
     * it. We are going to re-create it with new config again. */
    if (bundle->is_added_to_sim_ovs == true) {
        snprintf(cmd_str, MAX_CMD_LEN, "%s del-port %s", OVS_VSCTL,
                 bundle->name);
        if (system(cmd_str) != 0) {
            VLOG_ERR("Failed to delete the existing port. cmd=%s, rc=%s",
                     cmd_str, strerror(errno));
        }
        bundle->is_added_to_sim_ovs = false;
    }

    /* If this bundle is attached to VRF, there is no need to do any special
     * handling. Kernel will take care of routing. */
    if (ofproto->vrf) {
        return;
    }

    n_ports = list_size(&bundle->ports);

    /* If there is only one slave, then it should be a regular port not a
     * bundle. */
    if (n_ports == 1) {
        n = snprintf(cmd_str, MAX_CMD_LEN, "%s --may-exist add-port %s ",
                     OVS_VSCTL, ofproto->up.name);
    } else if (n_ports > 1) {
        n = snprintf(cmd_str, MAX_CMD_LEN, "%s --may-exist add-bond %s %s",
                     OVS_VSCTL, ofproto->up.name, bundle->name);
    } else {
        VLOG_INFO("Not enough ports to create a bundle, so skipping it.");
    }

    LIST_FOR_EACH_SAFE(port, next_port, bundle_node, &bundle->ports) {

        n += snprintf(&cmd_str[n], (MAX_CMD_LEN - n), " %s",
                      netdev_get_name(port->up.netdev));
        ovs_assert(n <= MAX_CMD_LEN);
    }

    /* Always configure bond_mode as balance-slb to get active-active links. */
    if (n_ports > 1) {
        n += snprintf(&cmd_str[n], (MAX_CMD_LEN - n), " bond_mode=balance-slb");
        ovs_assert(n <= MAX_CMD_LEN);
    }

    if (bundle->vlan_mode != PORT_VLAN_TRUNK) {
        if ((bundle->vlan > 0)
            && (bitmap_is_set(ofproto->vlans_bmp, bundle->vlan))) {
            n += snprintf(&cmd_str[n], (MAX_CMD_LEN - n), " tag=%d",
                          bundle->vlan);
            ovs_assert(n <= MAX_CMD_LEN);
        } else {
            goto done;
        }
    }

    /* The following logic is used for a port/bond in trunk mode:
     * If the configuration didn’t list any trunk VLAN, trunk all VLANs that
     * are enabled in the VLAN table (bit set in VLAN bitmap).
     * If the configuration does list trunk VLANs, configure all of the VLANs
     * in that list which are also enabled in the VLAN table.
     *
     * NOTE: If no VLANs are enabled in the VLAN bitmap, the port is not added
     * in the Internal "ASIC" OVS */

    if (bundle->vlan_mode != PORT_VLAN_ACCESS) {
        for (i = 1; i < 4095; i++) {
            if (bitmap_is_set(ofproto->vlans_bmp, i)) {
                if (!(bundle->trunks) || bitmap_is_set(bundle->trunks, i)) {

                    if (vlan_count == 0) {
                        n += snprintf(&cmd_str[n], (MAX_CMD_LEN - n),
                                      " trunks=%d", i);
                    } else {
                        n += snprintf(&cmd_str[n], (MAX_CMD_LEN - n), ",%d",
                                      i);
                    }

                    ovs_assert(n <= MAX_CMD_LEN);
                    vlan_count += 1;
                }
            }
        }
        /* If the trunk vlans are not defined in the global list. */
        if (vlan_count == 0) {
            goto done;
        }
    }

    if (bundle->vlan_mode == PORT_VLAN_ACCESS) {
        n += snprintf(&cmd_str[n], (MAX_CMD_LEN - n), " vlan_mode=access");
        ovs_assert(n <= MAX_CMD_LEN);

    } else if (bundle->vlan_mode == PORT_VLAN_TRUNK) {
        n += snprintf(&cmd_str[n], (MAX_CMD_LEN - n), " vlan_mode=trunk");
        ovs_assert(n <= MAX_CMD_LEN);

    } else if (bundle->vlan_mode == PORT_VLAN_NATIVE_UNTAGGED) {
        n += snprintf(&cmd_str[n], (MAX_CMD_LEN - n),
                      " vlan_mode=native-untagged");
        ovs_assert(n <= MAX_CMD_LEN);

    } else if (bundle->vlan_mode == PORT_VLAN_NATIVE_TAGGED) {
        n += snprintf(&cmd_str[n], (MAX_CMD_LEN - n),
                      " vlan_mode=native-tagged");
        ovs_assert(n <= MAX_CMD_LEN);
    }

    VLOG_DBG(cmd_str);

    if (system(cmd_str) != 0) {
        VLOG_ERR("Failed to create bundle. %s, %s", cmd_str, strerror(errno));
    } else {
        bundle->is_added_to_sim_ovs = true;
    }

done:
    /* Install IP table rules to prevent the traffic going to kernel IP stack.
     * When L2 switching is enabled on a port, ASIC OVS takes care of switching
     * the packets. We only depend on kernel to do L3 routing. */
    LIST_FOR_EACH_SAFE(port, next_port, bundle_node, &bundle->ports) {

        if (port->iptable_rules_added == false) {
            disable_port_in_iptables(netdev_get_name(port->up.netdev));
            port->iptable_rules_added = true;
        }
    }
#endif
    return 0;
err_ret:
    // XXX : clean-up as needed
    return ret_val;
}
#endif

/* Bundles. */
static int
bundle_set(struct ofproto *ofproto_, void *aux,
           const struct ofproto_bundle_settings *s)
{
    struct sim_provider_node *ofproto = sim_provider_node_cast(ofproto_);
    const struct ofport *ofport = NULL;
    bool ok = false;
    int ofp_port, i = 0, n = 0;
    char cmd_str[MAX_CMD_LEN];
    struct ofbundle *bundle;
    unsigned long *trunks = NULL;
    int ret_val = 0;

    if (s == NULL) {
        bundle_destroy(bundle_lookup(ofproto, aux));
        return 0;
    }
    VLOG_INFO("bundle_set: name %s, n_slaves %d, vlan_mode %d, vlan %d",
                s->name, s->n_slaves, s->vlan_mode, s->vlan);
#if 1
    // XXX LAG is not supported
    if (s->n_slaves > 1) {
        VLOG_ERR("LAG not supported");
        return EINVAL;
    }
#endif
    bundle = bundle_lookup(ofproto, aux);
    if (!bundle) {
        bundle = xmalloc(sizeof (struct ofbundle));

        bundle->ofproto = ofproto;
        hmap_insert(&ofproto->bundles, &bundle->hmap_node,
                    hash_pointer(aux, 0));
        bundle->aux = aux;
        bundle->name = NULL;

        list_init(&bundle->ports);
        bundle->vlan_mode = PORT_VLAN_ACCESS;
        bundle->vlan = -1;
        bundle->trunks = NULL;
        bundle->bond = NULL;
        bundle->is_added_to_sim_ovs = false;
        bundle->is_vlan_routing_enabled = false;
        bundle->is_bridge_bundle = false;
        bundle->tag_mode =  SWITCH_VLAN_PORT_UNTAGGED;
        bundle->port_type = SWITCH_API_INTERFACE_NONE;
        bundle->is_lag = false;
        bundle->if_handle = SWITCH_API_INVALID_HANDLE;
    }

    if (!bundle->name || strcmp(s->name, bundle->name)) {
        free(bundle->name);
        bundle->name = xstrdup(s->name);
    }

    // XXX code taken from container plug-in check and fix when LAG is supported
    /* Update set of ports. */
    ok = true;
    for (i = 0; i < s->n_slaves; i++) {
        if (!bundle_add_port(bundle, s->slaves[i])) {
            ok = false;
        }
    }

    if (!ok || list_size(&bundle->ports) != s->n_slaves) {
        struct sim_provider_ofport *next_port = NULL, *port = NULL;

        LIST_FOR_EACH_SAFE(port, next_port, bundle_node, &bundle->ports) {
            for (i = 0; i < s->n_slaves; i++) {
                if (s->slaves[i] == port->up.ofp_port) {
                    goto found;
                }
            }
            bundle_del_port(port);
found:     ;
        }
    }
    ovs_assert(list_size(&bundle->ports) <= s->n_slaves);

    if (list_is_empty(&bundle->ports)) {
        bundle_destroy(bundle);
        return EINVAL;
    }

    VLOG_DBG("Bridge/VRF name=%s type=%s bundle=%s",
             ofproto->up.name, ofproto->up.type, bundle->name);

    /* If it is bridge's internal bundle return from here. */
    if (bundle->is_bridge_bundle == true) {
        return 0;
    }

    /* Check if the given bundle is a VLAN routing enabled. */
    if (s->n_slaves == 1) {

        struct sim_provider_ofport *port = NULL;
        const char *type = NULL;

        port =
            sim_provider_ofport_cast(ofproto_get_port(ofproto_, s->slaves[0]));
        if (port) {
            type = netdev_get_type(port->up.netdev);
        }
        /* XXX : Internal interface are not support rightnow, just skip them */
        if (type &&
            (strcmp(type, OVSREC_INTERFACE_TYPE_INTERNAL) == 0)) {
            VLOG_DBG("XXX skip internal interfaces");
            return 0;
        }
    }

    /* If this bundle is attached to VRF, and it is a VLAN based internal
     * bundle, then there is no need to do any special handling. Kernel will
     * take care of routing. */
    if (ofproto->vrf == true) {
        return 0;
    }

#if 0
    /* If it is a bond, and there are less than two ports added to it, then
     * postpone creating this bond in ASIC OVS until at least two ports are
     * added to it. */
    if ((s->slaves_entered > 1) && s->n_slaves <= 1) {
        VLOG_INFO
            ("LAG Doesn't have enough interfaces to enable. So delaying the creation.");
        return 0;
    }
#endif

#if 1
    {
    /* Need to check the old and new bundle parmeters to handle transitions
     * Old          :   New
     * Access, v1   : Access, v2 -> delete pv1, create pv2
     * Access, v1   : Trunk -> delete pv1, delete intf, create intf, create all tunks
     * Trunk, v1    : Trunk, v2 -> delete pv1, create pv2
     * Trunk, vlans1: Trunk vlans2 -> delete pv(remove), create pv(added)
     * Trunk        : Access, v1 -> delete pv(all), delete intf, create intf, create pv1
     */
    int32_t new_port_type;
    int32_t tag_mode;

    /* XXX tag_mode is not supported yet. It is always untagged for native vlans */
    vlan_mode_to_port_type(s->vlan_mode, &new_port_type, &tag_mode);
    bundle->vlan_mode = s->vlan_mode;
    bundle->tag_mode = tag_mode;

    if (bundle->port_type != new_port_type) {
        // delete old interface and associated vlan_port
        p4_switch_interface_delete(bundle);
        bundle->port_type = new_port_type;
        p4_switch_interface_create(bundle);
    }

    if (new_port_type == SWITCH_API_INTERFACE_L2_VLAN_ACCESS) {
        if (bundle->vlan != s->vlan) {
            if (bundle->vlan != -1) {
                p4_switch_vlan_port_delete(bundle, bundle->vlan);
            }
            p4_switch_vlan_port_create(bundle, s->vlan);
            bundle->vlan = s->vlan;
        }
    } else if (bundle->port_type == SWITCH_API_INTERFACE_L2_VLAN_TRUNK) {
        int b;
        bool vlans_changed = false;
        // remove pv mapping for the vlans removed and add for the new ones
        for (b=0; b<VLAN_BITMAP_SIZE; b++) {
            bool vlan_old = false;
            bool vlan_new = false;
            if (bundle->trunks) {
                vlan_old = bitmap_is_set(bundle->trunks, b);
            }
            if (s->trunks) {
                vlan_new = bitmap_is_set(s->trunks, b);
            }
            if (vlan_old != vlan_new) {
                if (vlan_old) {
                    p4_switch_vlan_port_delete(bundle, b);
                }
                if (vlan_new) {
                    p4_switch_vlan_port_create(bundle, b);
                }
                vlans_changed = true;
            }
        }
        if (vlans_changed) {
            if (bundle->trunks) {
                free(bundle->trunks);
                bundle->trunks = NULL;
            }
            if (s->trunks) {
                bundle->trunks = vlan_bitmap_clone(CONST_CAST(unsigned long *, s->trunks));
            }
        }
    } else {
        // XXX un-supported interface
        VLOG_ERR("XXX un-supported interface type");
        return EINVAL;
    }
    } /* temp - remove */
#endif
    return ret_val;
}

static int
bundle_get(struct ofproto *ofproto_, void *aux, int *bundle_handle)
{
    return 0;
}

static int
bundle_set_reconfigure(struct ofproto *ofproto_, int vid)
{
#if 0
    struct sim_provider_node *ofproto = sim_provider_node_cast(ofproto_);
    struct ofbundle *bundle;

    HMAP_FOR_EACH(bundle, hmap_node, &ofproto->bundles) {

        /* bundles with VLAN routing enabled doesn't need re-configuration
         * when L2 VLan config is changed. */
        if ((bundle->is_vlan_routing_enabled == true) ||
            (bundle->is_bridge_bundle == true)) {

            continue;
        }

        /* Reconfiguring bundle with original configuration when VLAN is added
         * and deleting the bundle when corresponding VLAN gets deleted */
        bundle_configure(bundle);
    }
#endif
    return 0;
}

static void
bundle_remove(struct ofport *port_)
{
#if 0
    struct sim_provider_ofport *port = sim_provider_ofport_cast(port_);
    struct ofbundle *bundle = port->bundle;

    if (bundle) {
        bundle_del_port(port);

        /* If there are no ports left, delete the bunble. */
        if (list_is_empty(&bundle->ports)) {
            bundle_destroy(bundle);
        } else {
            /* Re-configure the bundle with new config. */
            bundle_configure(bundle);
        }
    }
#endif
}

// XXX:
// create a list of vlans to store handles for all the vlans created
// bundle: Add port_lag_handle union to store either port (single member bundle)
// of lag handle created
// set_vlan : add: go thru' all the bundles and create vlan_port for the new vlan
//          : del: delete vlan_port for all bundles, delete vlan handle
// bundle_set : trunk : add vlan_port for all vlans (check tagging mode for pvid vlan)
//            : access : add vlan_port for pvid/native vlan
// bundle_remove : trunk : remove port_vlan for all vlans
//                 access : remove pvid port_vlan
static int
set_vlan(struct ofproto *ofproto_, int vid, bool add)
{
    struct sim_provider_node *ofproto = sim_provider_node_cast(ofproto_);
    struct ofp4vlan *p4vlan;

    p4vlan = p4vlan_lookup(ofproto, (uint32_t)vid);
    if (add) {
        if (p4vlan) {
            VLOG_ERR("set_vlan: add vid %d, already exists", vid);
            return EEXIST;
        }
        VLOG_INFO("set_vlan: vid %d", vid);
        p4vlan = xmalloc(sizeof (struct ofp4vlan));
        p4vlan->vid = vid;
        // XXX device
        p4vlan->vlan_handle = switch_api_vlan_create(0, vid);
        VLOG_INFO("switch_api_vlan_create handle 0x%x", p4vlan->vlan_handle);
        hmap_insert(&ofproto->vlans, &p4vlan->hmap_node,
                    hash_int(vid, 0));
        // XXX add vlan to all applicable bundles
    } else {
        if (p4vlan == NULL) {
            VLOG_ERR("set_vlan: remove vid %d, does not exists", vid);
            return EINVAL;
        }
        VLOG_INFO("set_vlan: remove vid %d", vid);
        switch_api_vlan_delete(0, p4vlan->vlan_handle);
        hmap_remove(&ofproto->vlans, &p4vlan->hmap_node);
        // XXX remove vlan from all applicable bundles
        free(p4vlan);
    }
#if 0
    struct sim_provider_node *ofproto = sim_provider_node_cast(ofproto_);

    /* MAKE TO DBG */
    VLOG_DBG("%s: vid=%d, oper=%s", __FUNCTION__, vid, (add ? "add" : "del"));

    if (add) {

        /* If the vlan is already added to the list. */
        if (bitmap_is_set(ofproto->vlans_bmp, vid)) {
            return 0;
        }

        bitmap_set1(ofproto->vlans_bmp, vid);

    } else {

        /* If the vlan is already unset in the list. */
        if (!bitmap_is_set(ofproto->vlans_bmp, vid)) {
            return 0;
        }

        bitmap_set0(ofproto->vlans_bmp, vid);
    }

    if (ofproto->vrf == false) {
        bundle_set_reconfigure(ofproto_, vid);
    }
#endif
    return 0;
}

/* Mirrors. */
static int
mirror_get_stats__(struct ofproto *ofproto OVS_UNUSED, void *aux OVS_UNUSED,
                   uint64_t * packets OVS_UNUSED, uint64_t * bytes OVS_UNUSED)
{
    return 0;
}

static bool
is_mirror_output_bundle(const struct ofproto *ofproto_ OVS_UNUSED,
                        void *aux OVS_UNUSED)
{
    return false;
}

static void
forward_bpdu_changed(struct ofproto *ofproto_ OVS_UNUSED)
{
    return;
}

/* Ports. */

static struct sim_provider_ofport *
get_ofp_port(const struct sim_provider_node *ofproto, ofp_port_t ofp_port)
{
    struct ofport *ofport = ofproto_get_port(&ofproto->up, ofp_port);

    return ofport ? sim_provider_ofport_cast(ofport) : NULL;
}

static int
port_query_by_name(const struct ofproto *ofproto_, const char *devname,
                   struct ofproto_port *ofproto_port)
{
    struct sim_provider_node *ofproto = sim_provider_node_cast(ofproto_);
    const char *type = netdev_get_type_from_name(devname);

    VLOG_DBG("port_query_by_name - %s", devname);

    /* We must get the name and type from the netdev layer directly. */
    if (type) {
        const struct ofport *ofport;

        ofport = shash_find_data(&ofproto->up.port_by_name, devname);
        ofproto_port->ofp_port = ofport ? ofport->ofp_port : OFPP_NONE;
        ofproto_port->name = xstrdup(devname);
        ofproto_port->type = xstrdup(type);
        VLOG_DBG("get_ofp_port name= %s type= %s flow# %d",
                 ofproto_port->name, ofproto_port->type,
                 ofproto_port->ofp_port);
        return 0;
    }
    return ENODEV;

}

static int
port_add(struct ofproto *ofproto_, struct netdev *netdev)
{
    struct sim_provider_node *ofproto = sim_provider_node_cast(ofproto_);
    const char *devname = netdev_get_name(netdev);

    VLOG_INFO("port_add: %s", devname);
    // Lock before sset_add ??
    sset_add(&ofproto->ports, devname);
    // XXX switch_api_interface_create() - move to bundle_set ?
    // store the handle

    return 0;
}

static int
port_del(struct ofproto *ofproto_, ofp_port_t ofp_port)
{
    struct sim_provider_node *ofproto = sim_provider_node_cast(ofproto_);
    struct sim_provider_ofport *ofport = get_ofp_port(ofproto, ofp_port);
    int error = 0;

#if 0
    // XXX - need to find the name to delete
    if (sset_find(&ofproto->ports, xxx->name) == NULL) {
        VLOG_ERR("port_del - %s does not exists", xxx->name);
        return ENODEV;
    }

    // XXX switch_api_interface_delete()
    sset_delete(&ofproto->ports, xxx->name);
#endif
    return error;
}

static int
port_get_stats(const struct ofport *ofport_, struct netdev_stats *stats)
{
    struct sim_provider_ofport *ofport = sim_provider_ofport_cast(ofport_);
    int error;

    error = netdev_get_stats(ofport->up.netdev, stats);

    if (!error && ofport_->ofp_port == OFPP_LOCAL) {
        struct sim_provider_node *ofproto =
            sim_provider_node_cast(ofport->up.ofproto);

        ovs_mutex_lock(&ofproto->stats_mutex);
        /* ofproto->stats.tx_packets represents packets that we created
         * internally and sent to some port Account for them as if they had
         * come from OFPP_LOCAL and got forwarded. */

        if (stats->rx_packets != UINT64_MAX) {
            stats->rx_packets += ofproto->stats.tx_packets;
        }

        if (stats->rx_bytes != UINT64_MAX) {
            stats->rx_bytes += ofproto->stats.tx_bytes;
        }

        /* ofproto->stats.rx_packets represents packets that were received on
         * some port and we processed internally and dropped (e.g. STP).
         * Account for them as if they had been forwarded to OFPP_LOCAL. */

        if (stats->tx_packets != UINT64_MAX) {
            stats->tx_packets += ofproto->stats.rx_packets;
        }

        if (stats->tx_bytes != UINT64_MAX) {
            stats->tx_bytes += ofproto->stats.rx_bytes;
        }
        ovs_mutex_unlock(&ofproto->stats_mutex);
    }

    return error;
}

static int
port_dump_start(const struct ofproto *ofproto_ OVS_UNUSED, void **statep)
{
    VLOG_DBG("%s", __FUNCTION__);
    *statep = xzalloc(sizeof (struct sim_provider_port_dump_state));
    return 0;
}

static int
port_dump_next(const struct ofproto *ofproto_, void *state_,
               struct ofproto_port *port)
{
    struct sim_provider_node *ofproto = sim_provider_node_cast(ofproto_);
    struct sim_provider_port_dump_state *state = state_;
    const struct sset *sset;
    struct sset_node *node;

    if (state->has_port) {
        ofproto_port_destroy(&state->port);
        state->has_port = false;
    }
    sset = state->ghost ? &ofproto->ghost_ports : &ofproto->ports;
    while ((node = sset_at_position(sset, &state->bucket, &state->offset))) {
        int error;

        VLOG_DBG("port dump loop detecting port %s", node->name);

        error = port_query_by_name(ofproto_, node->name, &state->port);
        if (!error) {
            VLOG_DBG("port dump loop reporting port struct %s",
                     state->port.name);
            *port = state->port;
            state->has_port = true;
            return 0;
        } else if (error != ENODEV) {
            return error;
        }
    }

    if (!state->ghost) {
        state->ghost = true;
        state->bucket = 0;
        state->offset = 0;
        return port_dump_next(ofproto_, state_, port);
    }

    return EOF;
}

static int
port_dump_done(const struct ofproto *ofproto_ OVS_UNUSED, void *state_)
{
    struct sim_provider_port_dump_state *state = state_;

    if (state->has_port) {
        ofproto_port_destroy(&state->port);
    }
    free(state);
    return 0;
}

static struct sim_provider_rule
*
sim_provider_rule_cast(const struct rule *rule)
{
    return NULL;
}

static struct rule *
rule_alloc(void)
{
    struct sim_provider_rule *rule = xmalloc(sizeof *rule);

    return &rule->up;
}

static void
rule_dealloc(struct rule *rule_)
{
    struct sim_provider_rule *rule = sim_provider_rule_cast(rule_);

    free(rule);
}

static enum ofperr
rule_construct(struct rule *rule_ OVS_UNUSED)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    return 0;
}

static enum ofperr
rule_insert(struct rule *rule_ OVS_UNUSED)
OVS_REQUIRES(ofproto_mutex)
{
    return 0;
}

static void
rule_delete(struct rule *rule_ OVS_UNUSED)
OVS_REQUIRES(ofproto_mutex)
{
    return;
}

static void
rule_destruct(struct rule *rule_ OVS_UNUSED)
{
    return;
}

static void
rule_get_stats(struct rule *rule_ OVS_UNUSED, uint64_t * packets OVS_UNUSED,
               uint64_t * bytes OVS_UNUSED, long long int *used OVS_UNUSED)
{
    return;
}

static enum ofperr
rule_execute(struct rule *rule OVS_UNUSED, const struct flow *flow OVS_UNUSED,
             struct ofpbuf *packet OVS_UNUSED)
{
    return 0;
}

static void
rule_modify_actions(struct rule *rule_ OVS_UNUSED,
                    bool reset_counters OVS_UNUSED)
OVS_REQUIRES(ofproto_mutex)
{
    return;
}

static struct sim_provider_group
*
sim_provider_group_cast(const struct ofgroup *group)
{
    return group ? CONTAINER_OF(group, struct sim_provider_group, up) : NULL;
}

static struct ofgroup *
group_alloc(void)
{
    struct sim_provider_group *group = xzalloc(sizeof *group);

    return &group->up;
}

static void
group_dealloc(struct ofgroup *group_)
{
    struct sim_provider_group *group = sim_provider_group_cast(group_);

    free(group);
}

static enum ofperr
group_construct(struct ofgroup *group_ OVS_UNUSED)
{
    return 0;
}

static void
group_destruct(struct ofgroup *group_ OVS_UNUSED)
{
    return;
}

static enum ofperr
group_modify(struct ofgroup *group_ OVS_UNUSED)
{
    return 0;
}

static enum ofperr
group_get_stats(const struct ofgroup *group_ OVS_UNUSED,
                struct ofputil_group_stats *ogs OVS_UNUSED)
{
    return 0;
}

static const char *
get_datapath_version(const struct ofproto *ofproto_ OVS_UNUSED)
{
    struct sim_provider_node *ofproto = sim_provider_node_cast(ofproto_);

    return VERSION;
}

static bool
set_frag_handling(struct ofproto *ofproto_ OVS_UNUSED,
                  enum ofp_config_flags frag_handling OVS_UNUSED)
{
    return false;
}

static enum ofperr
packet_out(struct ofproto *ofproto_ OVS_UNUSED,
           struct ofpbuf *packet OVS_UNUSED,
           const struct flow *flow OVS_UNUSED,
           const struct ofpact *ofpacts OVS_UNUSED,
           size_t ofpacts_len OVS_UNUSED)
{
    return 0;
}

static void
get_netflow_ids(const struct ofproto *ofproto_ OVS_UNUSED,
                uint8_t * engine_type OVS_UNUSED,
                uint8_t * engine_id OVS_UNUSED)
{
    return;
}

#if 0
static enum ofperr
set_config(struct ofproto *ofproto_,
           ofp_port_t ofp_port, const struct smap *args)
{
    const struct ofport *ofport;
    const char *vlan_arg;

    ofproto_sim_provider_class;
    ofport = ofproto_get_port(ofproto_, ofp_port);

    if (ofport) {
        vlan_arg = smap_get(args, "vlan_default");
        VLOG_DBG("set_config port= %s ofp= %d option_arg= %s",
                 netdev_get_name(ofport->netdev), ofport->ofp_port, vlan_arg);
        return 0;
    } else {
        return ENODEV;
    }
}
#endif

// XXX
// set_stp() - can be used to install the STP reasoncode to send STP BPDUs to CPU
//

const struct ofproto_class ofproto_sim_provider_class = {
    init,
    enumerate_types,
    enumerate_names,
    del,
    port_open_type,
    NULL,                       /* may implement type_run */
    NULL,                       /* may implement type_wait */
    alloc,
    construct,
    destruct,
    dealloc,
    run,
    wait,
    NULL,                       /* get_memory_usage */
    NULL,                       /* may implement type_get_memory_usage */
    NULL,                       /* may implement flush */
    query_tables,
    port_alloc,
    port_construct,
    port_destruct,
    port_dealloc,
    NULL,                       /* may implement port_modified */
    port_reconfigured,
    port_query_by_name,
    port_add,
    port_del,
    port_get_stats,
    port_dump_start,
    port_dump_next,
    port_dump_done,
    NULL,                       /* may implement port_poll */
    NULL,                       /* may implement port_poll_wait */
    NULL,                       /* may implement port_is_lacp_current */
    NULL,                       /* may implement port_get_lacp_stats */
    NULL,                       /* rule_choose_table */
    rule_alloc,
    rule_construct,
    rule_insert,
    rule_delete,
    rule_destruct,
    rule_dealloc,
    rule_get_stats,
    rule_execute,
    NULL,                       /* rule_premodify_actions */
    rule_modify_actions,
    set_frag_handling,
    packet_out,
    NULL,                       /* may implement set_netflow */
    get_netflow_ids,
    NULL,                       /* may implement set_sflow */
    NULL,                       /* may implement set_ipfix */
    NULL,                       /* may implement set_cfm */
    cfm_status_changed,
    NULL,                       /* may implement get_cfm_status */
    NULL,                       /* may implement set_bfd */
    bfd_status_changed,
    NULL,                       /* may implement get_bfd_status */
    NULL,                       /* may implement set_stp */
    NULL,                       /* may implement get_stp_status */
    NULL,                       /* may implement set_stp_port */
    NULL,                       /* may implement get_stp_port_status */
    NULL,                       /* may implement get_stp_port_stats */
    NULL,                       /* may implement set_rstp */
    NULL,                       /* may implement get_rstp_status */
    NULL,                       /* may implement set_rstp_port */
    NULL,                       /* may implement get_rstp_port_status */
    NULL,                       /* may implement set_queues */
    bundle_set,
    bundle_remove,
    bundle_get,
    set_vlan,
    NULL,                       /* may implement mirror_set__ */
    mirror_get_stats__,
    NULL,                       /* may implement set_flood_vlans */
    is_mirror_output_bundle,
    forward_bpdu_changed,
    NULL,                       /* may implement set_mac_table_config */
    NULL,                       /* may implement set_mcast_snooping */
    NULL,                       /* may implement set_mcast_snooping_port */
    NULL,                       /* set_realdev, is unused */
    NULL,                       /* meter_get_features */
    NULL,                       /* meter_set */
    NULL,                       /* meter_get */
    NULL,                       /* meter_del */
    group_alloc,                /* group_alloc */
    group_construct,            /* group_construct */
    group_destruct,             /* group_destruct */
    group_dealloc,              /* group_dealloc */
    group_modify,               /* group_modify */
    group_get_stats,            /* group_get_stats */
    get_datapath_version,       /* get_datapath_version */
    NULL,                       /* Add l3 host entry */
    NULL,                       /* Delete l3 host entry */
    NULL,                       /* Get l3 host entry hit bits */
    NULL,                       /* l3 route action - install, update, delete */
    NULL,                       /* enable/disable ECMP globally */
    NULL,                       /* enable/disable ECMP hash configs */
};
