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

#define VLAN_BITMAP_SIZE    4096 /* XXX find if this is defined somewhere */

static void p4_switch_vlan_port_delete (struct ofbundle *bundle, int32_t vlan);
static void p4_switch_interface_delete (struct ofbundle *bundle);

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

    /* XXX documentation says caller has already cleared the names..
     * should not do it here ?
     * update name for types supported ("system" and "vrf")
     */
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
    /* XXX: comments indicate that for userspace DP (such as bmv2) type could be
     * reported as "tap"
     */
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

    if (!strcmp(ofproto_->type, "vrf")) {
        ofproto->vrf = true;
        VLOG_DBG("VRF name %s\n", ofproto_->name);
        /* XXX - Add switchapis to program vrf into the hardware */
    } else {
        ofproto->vrf = false;
    }

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

    /* report max ports supported by this plugin to ofproto layer */
    ofproto_init_max_ports(ofproto_, MAX_P4_SWITCH_PORTS);

    return error;
}

static void
destruct(struct ofproto *ofproto_ OVS_UNUSED)
{
    struct sim_provider_node *ofproto = sim_provider_node_cast(ofproto_);
    char ovs_delbr[80];

    if (ofproto->vrf == true) {
        /* XXX swithapi for vrf cleanup */
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

    /* XXX clean-up the provider_ofport structure - add the info as needed */
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
    /* XXX old_config is a bitmap (set of flags like down, no_rx....) */
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
    /* XXX: what is basis - initial value? use -1 */
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
    struct sim_provider_node *ofproto = bundle->ofproto;
    struct ofp4vlan *p4vlan;
    struct sim_provider_ofport *port = NULL, *next_port = NULL;

    VLOG_INFO("bundle_destroy %s", bundle->name);
    if (ofproto->vrf || bundle->is_bridge_bundle) {
        return;
    }
    p4_switch_interface_delete (bundle);

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
}

static void
vlan_mode_to_port_type(int32_t vlan_mode, int32_t *port_type, int32_t *tag_mode)
{
    ovs_assert(port_type && tag_mode);
    *port_type = SWITCH_API_INTERFACE_L2_VLAN_TRUNK;
    *tag_mode =  SWITCH_VLAN_PORT_UNTAGGED; /* XXX support other types */
    if (vlan_mode == PORT_VLAN_ACCESS) {
        *port_type = SWITCH_API_INTERFACE_L2_VLAN_ACCESS;
        *tag_mode = SWITCH_VLAN_PORT_UNTAGGED;
    } else if (vlan_mode == PORT_VLAN_TRUNK) {
        /* XXX */
    } else if (vlan_mode == PORT_VLAN_NATIVE_TAGGED) {
        /* XXX */
    } else if (vlan_mode == PORT_VLAN_NATIVE_UNTAGGED) {
        /* XXX */
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
    if (p4vlan && bundle->if_handle) {
        switch_vlan_port_t vlan_port;

        vlan_port.handle = bundle->if_handle;
        vlan_port.tagging_mode = bundle->tag_mode;
        VLOG_INFO("switch_api_vlan_ports_add - vlan 0x%x, port hdl 0x%x",
                    p4vlan->vlan_handle, vlan_port.handle);
        if (switch_api_vlan_ports_add(0, p4vlan->vlan_handle, 1, &vlan_port)) {
            VLOG_ERR("switch_api_vlan_ports_add - failed");
        }
    }
    return;
}

static void
p4_switch_vlan_port_delete (struct ofbundle *bundle, int32_t vlan)
{
    struct ofp4vlan *p4vlan;
    struct sim_provider_node *ofproto = bundle->ofproto;

    p4vlan = p4vlan_lookup(ofproto, vlan);
    if (p4vlan && bundle->if_handle) {
        switch_vlan_port_t vlan_port;

        vlan_port.handle = bundle->if_handle;
        vlan_port.tagging_mode = bundle->tag_mode;
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

    /* XXX use if_handle valid function from switchapi if available */
    ovs_assert(!P4_HANDLE_IS_VALID(bundle->if_handle));
    memset(&i_info, 0, sizeof(switch_api_interface_info_t));

    port = sim_provider_bundle_ofport_cast(list_front(&bundle->ports));

    if (bundle->is_lag) {
        /* XXX LAG not supported */
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
        /* No interface is created in P4 so far */
        return;
    }
    if (bundle->vlan != -1) {
        /* delete native/default vlan */
        p4_switch_vlan_port_delete(bundle, bundle->vlan);
        bundle->vlan = -1;
    }
    if (bundle->port_type == SWITCH_API_INTERFACE_L2_VLAN_ACCESS) {
        VLOG_INFO("switch_api_interface_delete(access) - if_handle 0x%x",
                    bundle->if_handle);
    }
    if (bundle->port_type == SWITCH_API_INTERFACE_L2_VLAN_TRUNK) {
        int b;
        if (bundle->trunks) {
            /* Delete pv mappings for all trunk vlans */
            for (b=0; b<VLAN_BITMAP_SIZE; b++) {
                if (bitmap_is_set(bundle->trunks, b)) {
                    VLOG_INFO("delete trunk vlan %d", b);
                    p4_switch_vlan_port_delete(bundle, b);
                }
            }
            free(bundle->trunks);
            bundle->trunks = NULL;
        }
        VLOG_INFO("switch_api_interface_delete (trunk) - if_handle 0x%x",
                    bundle->if_handle);
    }
    switch_api_interface_delete(0, bundle->if_handle);
    bundle->if_handle = SWITCH_API_INVALID_HANDLE;
    return;
}

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
    VLOG_INFO("bundle_set: name %s, n_slaves %d, vlan_mode %d, vlan %d, AUX = 0x%p, trunks = %p",
                s->name, s->n_slaves, s->vlan_mode, s->vlan, aux,
                s->trunks);
    /* XXX LAG is not supported */
    if (s->n_slaves > 1) {
        VLOG_ERR("LAG not supported");
        return EINVAL;
    }
    bundle = bundle_lookup(ofproto, aux);
    if (!bundle) {
        VLOG_INFO("bundle_set: New bundle name %s, aux 0x%p", s->name, aux);
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
        bundle->port_lag_handle = SWITCH_API_INVALID_HANDLE;
    }

    if (!bundle->name || strcmp(s->name, bundle->name)) {
        if (bundle->name) {
            free(bundle->name);
        }
        bundle->name = xstrdup(s->name);
    }

    /* XXX code taken from container plug-in check and fix when LAG is supported */
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

    VLOG_INFO("Bridge/VRF name=%s type=%s bundle=%s",
             ofproto->up.name, ofproto->up.type, bundle->name);

    if (s->n_slaves == 1) {

        struct sim_provider_ofport *port = NULL;
        const char *type = NULL;

        port =
            sim_provider_ofport_cast(ofproto_get_port(ofproto_, s->slaves[0]));
        if (port) {
            type = netdev_get_type(port->up.netdev);
        }
    }
    /* XXX If this bundle is attached to VRF or it is a VLAN based internal
     * bundle, then it is an L3 interface - TBD
     */
    if (ofproto->vrf == true) {
        VLOG_INFO("XXX L3 interface - skip");
        return 0;
    }

    /* If it is bridge's internal bundle return from here. */
    if(strcmp(bundle->name, "bridge_normal") == 0) {
        /* Setup system_Acl for the bridge
         * switchapi supports creating system_acls to redirect
         * certain tpye of packets to CPU.
         * Setup these ACLs to for STP, LLDP, LACP packets by default.
         * XXX - need to make then per-port/per-vlan in future
         */
        switch_api_hostif_rcode_info_t rcode_info;
        memset(&rcode_info, 0, sizeof(rcode_info));

        VLOG_INFO("Setup cpu redirect for stp, lldp and lacp packets");
        rcode_info.reason_code = SWITCH_HOSTIF_REASON_CODE_STP;
        rcode_info.action = SWITCH_ACL_ACTION_REDIRECT_TO_CPU;
        rcode_info.priority = 0;
        rcode_info.channel = SWITCH_HOSTIF_CHANNEL_NETDEV;
        rcode_info.hostif_group_id = 0;
        switch_api_hostif_reason_code_create(0, &rcode_info);

        rcode_info.reason_code = SWITCH_HOSTIF_REASON_CODE_LACP;
        switch_api_hostif_reason_code_create(0, &rcode_info);

        rcode_info.reason_code = SWITCH_HOSTIF_REASON_CODE_LLDP;
        switch_api_hostif_reason_code_create(0, &rcode_info);

        bundle->is_bridge_bundle = true;

        return 0;
    }

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
        /* delete old interface and associated vlan_port */
        p4_switch_interface_delete(bundle);
        bundle->port_type = new_port_type;
        p4_switch_interface_create(bundle);
    }

    /* XXX looks like native vlan for the trunk is not included in trunks bitmap */
    if (bundle->vlan != s->vlan) {
        struct ofp4vlan *p4vlan;

        if (bundle->vlan != -1) {
            p4_switch_vlan_port_delete(bundle, bundle->vlan);
            bundle->vlan = -1;
        }
        p4vlan = p4vlan_lookup(ofproto, (uint32_t)s->vlan);
        if (p4vlan && new_port_type == SWITCH_API_INTERFACE_L2_VLAN_TRUNK) {
            switch_api_interface_native_vlan_set(bundle->if_handle, p4vlan->vlan_handle);
        }
        p4_switch_vlan_port_create(bundle, s->vlan);
        bundle->vlan = s->vlan;
    }
    if (new_port_type == SWITCH_API_INTERFACE_L2_VLAN_ACCESS) {
        /* Access(natvie) vlan is handled above */
    } else if (new_port_type == SWITCH_API_INTERFACE_L2_VLAN_TRUNK) {
        int b;
        bool vlans_changed = false;
        /* remove pv mapping for the vlans removed and add for the new ones
         * XXX loop thru' vlans and add/remove only those ?? faster?
         */
        for (b=0; b<VLAN_BITMAP_SIZE; b++) {
            bool vlan_old = false;
            bool vlan_new = false;
            /* XXX if trunks == NULL => implicitly add all vlans  ??? */
            /* if (!bundle->trunks || bitmap_is_set(bundle->trunks, b)) */
            if (bundle->trunks && bitmap_is_set(bundle->trunks, b))
            {
                vlan_old = true;
            }
            /* if (!s->trunks || bitmap_is_set(s->trunks, b)) */
            if (s->trunks && bitmap_is_set(s->trunks, b))
            {
                vlan_new = true;
            }
            if (vlan_old != vlan_new) {
                if (vlan_old) {
                    /* For a newly created interface,
                     * old_vlans are not yet programmed in the h/w
                     */
                    VLOG_INFO("bundle_set - Delete old trunk vlan %d", b);
                    p4_switch_vlan_port_delete(bundle, b);
                }
                if (vlan_new) {
                    VLOG_INFO("bundle_set - Add new trunk vlan %d", b);
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
        VLOG_ERR("un-supported interface type");
        return EINVAL;
    }
    VLOG_INFO("bundle_set - Done");
    } /* temp - remove */
#endif
    return ret_val;
}

static int
bundle_get(struct ofproto *ofproto_, void *aux, int *bundle_handle)
{
    struct sim_provider_node *ofproto = sim_provider_node_cast(ofproto_);
    struct ofbundle *bundle;

    bundle = bundle_lookup(ofproto, aux);
    if (bundle && P4_HANDLE_IS_VALID(bundle->if_handle)) {
        *bundle_handle = bundle->if_handle;
    } else {
        *bundle_handle = -1;
    }
    return 0;
}

static void
bundle_remove(struct ofport *port_)
{
    struct sim_provider_ofport *port = sim_provider_ofport_cast(port_);
    struct ofbundle *bundle = port->bundle;

    if (bundle) {
        VLOG_INFO("bundle_remove port bundle %s port %s", bundle->name,
                    netdev_get_name(port_->netdev));
        bundle_del_port(port);

        /* If there are no ports left, delete the bunble. */
        if (list_is_empty(&bundle->ports)) {
            bundle_destroy(bundle);
        }
    }
}

static void
p4_bundles_vlan_update (struct sim_provider_node *ofproto, struct ofp4vlan *p4vlan, bool add)
{
    /* iterate over all bundles and add new port_vlan mapping for the new vlan
     * skip over the non-L2 bundles and special bridge_normal bundle
     */
    struct ofbundle *bundle;
    int max_bundles = hmap_count(&ofproto->bundles);
    int l2_bundles = 0;
    switch_vlan_port_t *vlan_port;

    vlan_port = xmalloc(max_bundles * sizeof(switch_vlan_port_t));
    ovs_assert(vlan_port);

    HMAP_FOR_EACH(bundle, hmap_node, &ofproto->bundles) {
        if (ofproto->vrf || bundle->is_bridge_bundle) {
            continue;
        }
        /* skip if the bundle is not a member of this vlan */
        if ((bundle->vlan != p4vlan->vid) &&
            (!bundle->trunks || !bitmap_is_set(bundle->trunks, p4vlan->vid))) {
            /* XXX - not clear If trunks == NULL implies all-vlans or not ?? */
            continue;
        }
        VLOG_INFO("Update vlan %d on bundle %s", p4vlan->vid, bundle->name);
        vlan_port[l2_bundles].handle = bundle->if_handle;
        vlan_port[l2_bundles].tagging_mode = bundle->tag_mode;
        l2_bundles++;
    }
    if (l2_bundles == 0) {
        VLOG_INFO("p4_bundles_vlan_update - no bundles found");
        free(vlan_port);
        return;
    }
    if (add) {
        VLOG_INFO("switch_api_vlan_ports_add vlan_hdl 0x%x, n_ports %d",
                        p4vlan->vlan_handle, l2_bundles);
        if (switch_api_vlan_ports_add(0, p4vlan->vlan_handle, l2_bundles, vlan_port)) {
            VLOG_ERR("switch_api_vlan_ports_add - failed");
        }
    } else {
        VLOG_INFO("switch_api_vlan_ports_remove vlan_hdl 0x%x, n_ports %d",
                        p4vlan->vlan_handle, l2_bundles);
        if (switch_api_vlan_ports_remove(0, p4vlan->vlan_handle, l2_bundles, vlan_port)) {
            VLOG_ERR("switch_api_vlan_ports_remove - failed");
        }
    }
    free(vlan_port);
}

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
        /* add vlan to all applicable bundles */
        p4_bundles_vlan_update(ofproto, p4vlan, true/*add*/);
    } else {
        if (p4vlan == NULL) {
            VLOG_ERR("set_vlan: remove vid %d, does not exists", vid);
            return EINVAL;
        }
        VLOG_INFO("set_vlan: remove vid %d", vid);
        switch_api_vlan_delete(0, p4vlan->vlan_handle);
        hmap_remove(&ofproto->vlans, &p4vlan->hmap_node);
        /* remove vlan from all applicable bundles */
        p4_bundles_vlan_update(ofproto, p4vlan, false/*add*/);
        free(p4vlan);
    }
    VLOG_INFO("set_vlan - Done");
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

    return 0;
}

static int
port_del(struct ofproto *ofproto_, ofp_port_t ofp_port)
{
    struct sim_provider_node *ofproto = sim_provider_node_cast(ofproto_);
    struct sim_provider_ofport *ofport = get_ofp_port(ofproto, ofp_port);
    char *netdev_name = NULL;

    ovs_assert(ofport);
    netdev_name = netdev_get_name(ofport->up.netdev);
    VLOG_DBG("port_del: %d, name = %s", ofp_port, netdev_name);
    if (!sset_find_and_delete(&ofproto->ports, netdev_name)) {
        VLOG_ERR("port_del - %s does not exists", netdev_name);
        return ENODEV;
    }
    return 0;
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
