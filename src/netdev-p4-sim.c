/*
 * Copyright (c) 2010, 2011, 2012, 2013 Nicira, Inc.
 * Copyright (C) 2015 Hewlett-Packard Development Company, L.P.
 * Copyright (C) 2016 Barefoot Networks Inc.
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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <linux/ethtool.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <netinet/ether.h>

#include <openswitch-idl.h>

#include "p4-switch.h"
#include "openvswitch/vlog.h"
#include "netdev-p4-sim.h"


#define SWNS_EXEC       "/sbin/ip netns exec swns"
#define EMULNS_EXEC     "/sbin/ip netns exec emulns"

VLOG_DEFINE_THIS_MODULE(P4_netdev_sim);

/* Protects 'sim_list'. */
static struct ovs_mutex sim_list_mutex = OVS_MUTEX_INITIALIZER;

/* Contains all 'struct sim_dev's. */
static struct ovs_list sim_list OVS_GUARDED_BY(sim_list_mutex)
    = OVS_LIST_INITIALIZER(&sim_list);

struct netdev_sim {
    struct netdev up;

    /* In sim_list. */
    struct ovs_list list_node OVS_GUARDED_BY(sim_list_mutex);

    /* Protects all members below. */
    struct ovs_mutex mutex OVS_ACQ_AFTER(sim_list_mutex);

    uint8_t hwaddr[ETH_ADDR_LEN] OVS_GUARDED;
    char hw_addr_str[18];
    struct netdev_stats stats OVS_GUARDED;
    enum netdev_flags flags OVS_GUARDED;

    char linux_intf_name[16];
    int link_state;
    uint32_t hw_info_link_speed;
    uint32_t link_speed;
    uint32_t mtu;
    bool autoneg;
    bool pause_tx;
    bool pause_rx;

    /* p4 target related information */
    uint32_t port_num;
    switch_handle_t hostif_handle;
    switch_handle_t port_handle;
};

static int netdev_sim_construct(struct netdev *);

static bool
is_sim_class(const struct netdev_class *class)
{
    return class->construct == netdev_sim_construct;
}

static struct netdev_sim *
netdev_sim_cast(const struct netdev *netdev)
{
    ovs_assert(is_sim_class(netdev_get_class(netdev)));
    return CONTAINER_OF(netdev, struct netdev_sim, up);
}

static struct netdev *
netdev_sim_alloc(void)
{
    struct netdev_sim *netdev = xzalloc(sizeof *netdev);
    return &netdev->up;
}

static int
netdev_sim_construct(struct netdev *netdev_)
{
    static atomic_count next_n = ATOMIC_COUNT_INIT(0x0000);
    struct netdev_sim *netdev = netdev_sim_cast(netdev_);
    unsigned int n;
    unsigned int mac = 0xBA7EF008; /* BA7EF008 = Barefoot */

    n = atomic_count_inc(&next_n);

    VLOG_INFO("sim construct for port %s", netdev->up.name);

    ovs_mutex_init(&netdev->mutex);
    ovs_mutex_lock(&netdev->mutex);
    netdev->hwaddr[0] = 0x00;
    netdev->hwaddr[1] = mac >> 24;
    netdev->hwaddr[2] = mac >> 16;
    netdev->hwaddr[3] = mac >> 8;
    netdev->hwaddr[4] = mac;
    netdev->hwaddr[5] = n;
    netdev->mtu = 1500;
    netdev->flags = 0;
    netdev->link_state = 0;
    netdev->hostif_handle = SWITCH_API_INVALID_HANDLE;
    netdev->port_handle = SWITCH_API_INVALID_HANDLE;
    ovs_mutex_unlock(&netdev->mutex);

    ovs_mutex_lock(&sim_list_mutex);
    list_push_back(&sim_list, &netdev->list_node);
    ovs_mutex_unlock(&sim_list_mutex);

    return 0;
}

static void
netdev_sim_destruct(struct netdev *netdev_)
{
    struct netdev_sim *netdev = netdev_sim_cast(netdev_);

    ovs_mutex_lock(&sim_list_mutex);
    list_remove(&netdev->list_node);
    ovs_mutex_unlock(&sim_list_mutex);
}

static void
netdev_sim_dealloc(struct netdev *netdev_)
{
    struct netdev_sim *netdev = netdev_sim_cast(netdev_);

    free(netdev);
}

static void
netdev_sim_run(void)
{
    /* TODO - if needed */
}

static int
netdev_sim_internal_set_hw_intf_info(struct netdev *netdev_, const struct smap *args)
{
    struct netdev_sim *netdev = netdev_sim_cast(netdev_);
    const char *mac_addr = smap_get(args, INTERFACE_HW_INTF_INFO_MAP_MAC_ADDR);

    ovs_mutex_lock(&netdev->mutex);
    strncpy(netdev->linux_intf_name, netdev->up.name, sizeof(netdev->linux_intf_name));
    VLOG_INFO("TBD - internal_set_hw_intf_info for %s", netdev->linux_intf_name);
    if(mac_addr != NULL) {
        strncpy(netdev->hw_addr_str, mac_addr, sizeof(netdev->hw_addr_str));
    } else {
        VLOG_ERR("Invalid mac address %s", mac_addr);
    }
    ovs_mutex_unlock(&netdev->mutex);
    return 0;
}

static int
netdev_sim_set_hw_intf_info(struct netdev *netdev_, const struct smap *args)
{
    struct netdev_sim *netdev = netdev_sim_cast(netdev_);
    const char *max_speed = smap_get(args, INTERFACE_HW_INTF_INFO_MAP_MAX_SPEED);
    const char *mac_addr = smap_get(args, INTERFACE_HW_INTF_INFO_MAP_MAC_ADDR);
    const char *hw_id = smap_get(args, INTERFACE_HW_INTF_INFO_MAP_SWITCH_INTF_ID);
    const char *is_splittable = smap_get(args, INTERFACE_HW_INTF_INFO_MAP_SPLIT_4);
    const char *split_parent = smap_get(args, INTERFACE_HW_INTF_INFO_SPLIT_PARENT);

    char cmd[MAX_CMD_BUF];

    ovs_mutex_lock(&netdev->mutex);

    strncpy(netdev->linux_intf_name, netdev->up.name, sizeof(netdev->linux_intf_name));

    VLOG_INFO("set_hw_intf for interface, %s", netdev->linux_intf_name);

    /* There are no splittable interfaces supported by P4 model */
    if ((is_splittable && !strncmp(is_splittable, "true", 4)) ||
        (mac_addr == NULL) || split_parent) {
        VLOG_DBG("Split interface or NULL MAC is not supported- parent i/f %s",
                    split_parent ? split_parent : "NotSpecified");
        ovs_mutex_unlock(&netdev->mutex);
        return EINVAL;
    }
    if (netdev->port_handle == SWITCH_API_INVALID_HANDLE) {
        if (hw_id) {
            netdev->port_num = atoi(hw_id);
            /* switchapi uses 0 based port# */
            netdev->port_handle = id_to_handle(SWITCH_HANDLE_TYPE_PORT,
                                                        netdev->port_num-1);
            VLOG_INFO("set_hw_intf create tap interface for port, %d",
                                                        netdev->port_num);

            if (mac_addr) {
                struct ether_addr *ether_mac = ether_aton(mac_addr);
                if (ether_mac != NULL) {
                    memcpy(netdev->hwaddr, ether_mac, ETH_ALEN);
                }
            }

            /* create a tap interface */
            sprintf(cmd, "%s /sbin/ip tuntap add dev %s mode tap",
                    SWNS_EXEC, netdev->linux_intf_name);

            if (system(cmd) != 0) {
                VLOG_ERR("NETDEV-SIM | system command failure cmd=%s", cmd);
            }
            if (netdev->hostif_handle == SWITCH_API_INVALID_HANDLE) {
                switch_hostif_t     hostif;
                memset(&hostif, 0, sizeof(hostif));
                hostif.handle = netdev->port_handle;
                strncpy(hostif.intf_name, netdev->linux_intf_name, sizeof(hostif.intf_name));
                netdev->hostif_handle = switch_api_hostif_create(0, &hostif);
                VLOG_INFO("switch_api_hostif_create handle 0x%x", netdev->hostif_handle);
            }
        } else {
            VLOG_ERR("No hw_id available");
            ovs_mutex_unlock(&netdev->mutex);
            return EINVAL;
        }
    }

    /* In simulator it is assumed that interfaces always
     * link up at max_speed listed in hardware info. */
    if(max_speed)
        netdev->hw_info_link_speed = atoi(max_speed);

    sprintf(cmd, "%s /sbin/ip link set dev %s down",
            SWNS_EXEC, netdev->linux_intf_name);
    if (system(cmd) != 0) {
        VLOG_ERR("NETDEV-SIM | system command failure cmd=%s", cmd);
    }

    if(mac_addr != NULL) {
        strncpy(netdev->hw_addr_str, mac_addr, sizeof(netdev->hw_addr_str));
    } else {
        VLOG_ERR("Invalid mac address %s", mac_addr);
    }

    sprintf(cmd, "%s /sbin/ip link set %s address %s",
            SWNS_EXEC, netdev->up.name, netdev->hw_addr_str);
    if (system(cmd) != 0) {
        VLOG_ERR("NETDEV-SIM | system command failure cmd=%s", cmd);
    }

    sprintf(cmd, "%s /sbin/ip link set dev %s up",
            SWNS_EXEC, netdev->linux_intf_name);
    if (system(cmd) != 0) {
        VLOG_ERR("NETDEV-SIM | system command failure cmd=%s", cmd);
    }

    ovs_mutex_unlock(&netdev->mutex);

    return 0;
}

static void
get_interface_pause_config(const char *pause_cfg, bool *pause_rx, bool *pause_tx)
{
    *pause_rx = false;
    *pause_tx = false;

        /* Pause configuration. */
    if (STR_EQ(pause_cfg, INTERFACE_HW_INTF_CONFIG_MAP_PAUSE_RX)) {
        *pause_rx = true;
    } else if (STR_EQ(pause_cfg, INTERFACE_HW_INTF_CONFIG_MAP_PAUSE_TX)) {
        *pause_tx = true;
    } else if (STR_EQ(pause_cfg, INTERFACE_HW_INTF_CONFIG_MAP_PAUSE_RXTX)) {
        *pause_rx = true;
        *pause_tx = true;
    }
}

static int
netdev_sim_internal_set_hw_intf_config(struct netdev *netdev_, const struct smap *args)
{
    struct netdev_sim *netdev = netdev_sim_cast(netdev_);
    const bool hw_enable = smap_get_bool(args, INTERFACE_HW_INTF_CONFIG_MAP_ENABLE, false);

    ovs_mutex_lock(&netdev->mutex);
    strncpy(netdev->linux_intf_name, netdev->up.name, sizeof(netdev->linux_intf_name));
    /* XXX handle internal interface up/down - SVI and bridge_normal */
    VLOG_INFO("TBD - netdev_sim_internal_set_hw_intf_config for %s, enable $d",
               netdev->linux_intf_name, hw_enable);
    ovs_mutex_unlock(&netdev->mutex);
    return 0;
}

#if 0
/* XXX not needed for loopback interface? - confirm */
static int
netdev_sim_loopback_set_hw_intf_config(struct netdev *netdev_, const struct smap *args)
{
    struct netdev_sim *netdev = netdev_sim_cast(netdev_);
    const bool hw_enable = smap_get_bool(args, INTERFACE_HW_INTF_CONFIG_MAP_ENABLE, false);

    ovs_mutex_lock(&netdev->mutex);
    strncpy(netdev->linux_intf_name, netdev->up.name, sizeof(netdev->linux_intf_name));
    VLOG_INFO("netdev_sim_loopback_set_hw_intf_config for %s, enable $d",
               netdev->linux_intf_name, hw_enable);
    if(hw_enable) {
        netdev->flags |= NETDEV_UP;
        netdev->link_state = 1;
    } else {
        netdev->flags &= ~NETDEV_UP;
        netdev->link_state = 0;
    }
    ovs_mutex_unlock(&netdev->mutex);
    return 0;
}
#endif


static int
netdev_sim_set_hw_intf_config(struct netdev *netdev_, const struct smap *args)
{
    char cmd[80];
    struct netdev_sim *netdev = netdev_sim_cast(netdev_);
    const bool hw_enable = smap_get_bool(args, INTERFACE_HW_INTF_CONFIG_MAP_ENABLE, false);
    const bool autoneg = smap_get_bool(args, INTERFACE_HW_INTF_CONFIG_MAP_AUTONEG, false);
    const char *pause = smap_get(args, INTERFACE_HW_INTF_CONFIG_MAP_PAUSE);
    const int mtu = smap_get_int(args, INTERFACE_HW_INTF_CONFIG_MAP_MTU, 0);

    ovs_mutex_lock(&netdev->mutex);

    VLOG_DBG("Interface=%s hw_enable=%d ", netdev->linux_intf_name, hw_enable);

    memset(cmd, 0, sizeof(cmd));

    if (hw_enable) {
        switch_hostif_t     hostif;

        netdev->flags |= NETDEV_UP;
        netdev->link_state = 1;

        /* In simulator Links always come up at its max speed. */
        netdev->link_speed = netdev->hw_info_link_speed;
        netdev->mtu = mtu;
        netdev->autoneg = autoneg;
        if(pause)
            get_interface_pause_config(pause, &(netdev->pause_rx), &(netdev->pause_tx));
    } else {
        netdev->flags &= ~NETDEV_UP;
        netdev->link_state = 0;
        netdev->link_speed = 0;
        netdev->mtu = 0;
        netdev->autoneg = false;
        netdev->pause_tx = false;
        netdev->pause_rx = false;
    }
    sprintf(cmd, "%s /sbin/ip link set dev %s %s",
                SWNS_EXEC, netdev->linux_intf_name, hw_enable ? "up" : "down");
    if (system(cmd) != 0) {
        VLOG_ERR("system command failure: cmd=%s",cmd);
    }

    /* Operate on emulns interface that feed into the model */
    sprintf(cmd, "%s /sbin/ip link set dev %s %s",
                EMULNS_EXEC, netdev->linux_intf_name, hw_enable ? "up" : "down");
    system(cmd);

    netdev_change_seq_changed(netdev_);

    ovs_mutex_unlock(&netdev->mutex);
    return 0;
}

static int
netdev_sim_set_etheraddr(struct netdev *netdev,
                           const struct eth_addr mac)
{
    struct netdev_sim *dev = netdev_sim_cast(netdev);

    ovs_mutex_lock(&dev->mutex);
    if (memcmp(dev->hwaddr, mac.ea, ETH_ADDR_LEN)) {
        memcpy(dev->hwaddr, mac.ea, ETH_ADDR_LEN);
        netdev_change_seq_changed(netdev);
    }
    ovs_mutex_unlock(&dev->mutex);

    return 0;
}

extern int
netdev_sim_get_etheraddr(const struct netdev *netdev,
                           struct eth_addr *mac)
{
    struct netdev_sim *dev = netdev_sim_cast(netdev);

    ovs_mutex_lock(&dev->mutex);
    memcpy(mac->ea, dev->hwaddr, ETH_ADDR_LEN);
    ovs_mutex_unlock(&dev->mutex);

    return 0;
}

static int
netdev_sim_internal_get_stats(const struct netdev *netdev, struct netdev_stats *stats)
{
    struct netdev_sim *dev = netdev_sim_cast(netdev);

    /* XXX handle internal interface stats - SVI and bridge_normal */
    ovs_mutex_lock(&dev->mutex);
    *stats = dev->stats;
    ovs_mutex_unlock(&dev->mutex);

    return 0;
}

static void
netdev_p4_port_stats_copy(struct netdev_stats *stats, struct p4_port_stats *p4_stats)
{
    ovs_assert(stats && p4_stats);
    memset(stats, 0, sizeof(struct netdev_stats));

    stats->rx_packets = p4_stats->rx_packets;
    stats->tx_packets = p4_stats->tx_packets;
    stats->rx_bytes = p4_stats->rx_bytes;
    stats->tx_bytes = p4_stats->tx_bytes;
    stats->rx_errors = p4_stats->rx_errors;
    stats->tx_errors = p4_stats->tx_errors;
    stats->rx_dropped = p4_stats->rx_dropped;
    stats->tx_dropped = p4_stats->tx_dropped;
    stats->multicast = p4_stats->multicast;
    stats->collisions = p4_stats->collisions;
    stats->rx_crc_errors = p4_stats->rx_crc_errors;
}

static int
netdev_sim_get_stats(const struct netdev *netdev, struct netdev_stats *stats)
{
    struct netdev_sim *dev = netdev_sim_cast(netdev);
    int rc = 0;
    struct p4_port_stats port_stats;

    memset(&port_stats, 0, sizeof(port_stats));
    ovs_mutex_lock(&dev->mutex);
    rc = p4_port_stats_get(dev->linux_intf_name, &port_stats);
    netdev_p4_port_stats_copy(&dev->stats,&port_stats);
    *stats = dev->stats;
    ovs_mutex_unlock(&dev->mutex);

    return 0;
}

static int
netdev_sim_get_features(const struct netdev *netdev_,
                        enum netdev_features *current,
                        enum netdev_features *advertised,
                        enum netdev_features *supported,
                        enum netdev_features *peer)
{
    struct netdev_sim *netdev = netdev_sim_cast(netdev_);

    ovs_mutex_lock(&netdev->mutex);

    *current = 0;

    /* Current settings. */
    if (netdev->link_speed == SPEED_10) {
        *current |= NETDEV_F_10MB_FD;
    } else if (netdev->link_speed == SPEED_100) {
        *current |= NETDEV_F_100MB_FD;
    } else if (netdev->link_speed == SPEED_1000) {
        *current |= NETDEV_F_1GB_FD;
    } else if (netdev->link_speed == SPEED_10000) {
        *current |= NETDEV_F_10GB_FD;
    } else if (netdev->link_speed == 40000) {
        *current |= NETDEV_F_40GB_FD;
    } else if (netdev->link_speed == 100000) {
        *current |= NETDEV_F_100GB_FD;
    }

    if (netdev->autoneg) {
        *current |= NETDEV_F_AUTONEG;
    }

    if (netdev->pause_tx && netdev->pause_rx) {
        *current |= NETDEV_F_PAUSE;
    } else if (netdev->pause_rx) {
        *current |= NETDEV_F_PAUSE;
        *current |= NETDEV_F_PAUSE_ASYM;
    } else if (netdev->pause_tx) {
        *current |= NETDEV_F_PAUSE_ASYM;
    }

    ovs_mutex_unlock(&netdev->mutex);

    return 0;
}

static int
netdev_sim_update_flags(struct netdev *netdev_,
                          enum netdev_flags off, enum netdev_flags on,
                          enum netdev_flags *old_flagsp)
{
    struct netdev_sim *netdev = netdev_sim_cast(netdev_);

    /* HALON_TODO: Currently we are not supporting changing the
     * configuration using the FLAGS. So ignoring the
     * incoming on/off flags. */
    if ((off | on) & ~(NETDEV_UP | NETDEV_PROMISC)) {
        return EINVAL;
    }

    ovs_mutex_lock(&netdev->mutex);
    *old_flagsp = netdev->flags;
    ovs_mutex_unlock(&netdev->mutex);

    return 0;
}

static int
netdev_sim_get_carrier(const struct netdev *netdev_, bool *carrier)
{
    struct netdev_sim *netdev = netdev_sim_cast(netdev_);

    ovs_mutex_lock(&netdev->mutex);
    *carrier = netdev->link_state;
    ovs_mutex_unlock(&netdev->mutex);

    return 0;
}

/* Helper functions. */
int netdev_get_device_port_handle(struct netdev *netdev_,
                int32_t *device, switch_handle_t *port_handle)
{
    struct netdev_sim *netdev = netdev_sim_cast(netdev_);
    *device = 0;
    *port_handle = netdev->port_handle;
    return 0;
}

static const struct netdev_class sim_class = {
    "system",
    NULL,                       /* init */
    netdev_sim_run,
    NULL,                       /* wait */

    netdev_sim_alloc,
    netdev_sim_construct,
    netdev_sim_destruct,
    netdev_sim_dealloc,
    NULL,                       /* get_config */
    NULL,                       /* set_config */
    netdev_sim_set_hw_intf_info,
    netdev_sim_set_hw_intf_config,
    NULL,                       /* get_tunnel_config */
    NULL,                       /* build header */
    NULL,                       /* push header */
    NULL,                       /* pop header */
    NULL,                       /* get_numa_id */
    NULL,                       /* set_multiq */

    NULL,                       /* send */
    NULL,                       /* send_wait */

    netdev_sim_set_etheraddr,
    netdev_sim_get_etheraddr,
    NULL,                       /* get_mtu */
    NULL,                       /* set_mtu */
    NULL,                       /* get_ifindex */
    netdev_sim_get_carrier,
    NULL,                       /* get_carrier_resets */
    NULL,                       /* get_miimon */
    netdev_sim_get_stats,

    netdev_sim_get_features,    /* get_features */
    NULL,                       /* set_advertisements */

    NULL,                       /* set_policing */
    NULL,                       /* get_qos_types */
    NULL,                       /* get_qos_capabilities */
    NULL,                       /* get_qos */
    NULL,                       /* set_qos */
    NULL,                       /* get_queue */
    NULL,                       /* set_queue */
    NULL,                       /* delete_queue */
    NULL,                       /* get_queue_stats */
    NULL,                       /* queue_dump_start */
    NULL,                       /* queue_dump_next */
    NULL,                       /* queue_dump_done */
    NULL,                       /* dump_queue_stats */

    NULL,                       /* get_in4 */
    NULL,                       /* set_in4 */
    NULL,                       /* get_in6 */
    NULL,                       /* add_router */
    NULL,                       /* get_next_hop */
    NULL,                       /* get_status */
    NULL,                       /* arp_lookup */

    netdev_sim_update_flags,

    NULL,                       /* rxq_alloc */
    NULL,                       /* rxq_construct */
    NULL,                       /* rxq_destruct */
    NULL,                       /* rxq_dealloc */
    NULL,                       /* rxq_recv */
    NULL,                       /* rxq_wait */
    NULL,                       /* rxq_drain */
};

static const struct netdev_class sim_internal_class = {
    "internal",
    NULL,                       /* init */
    netdev_sim_run,
    NULL,                       /* wait */

    netdev_sim_alloc,
    netdev_sim_construct,
    netdev_sim_destruct,
    netdev_sim_dealloc,
    NULL,                       /* get_config */
    NULL,                       /* set_config */
    netdev_sim_internal_set_hw_intf_info,
    netdev_sim_internal_set_hw_intf_config,
    NULL,                       /* get_tunnel_config */
    NULL,                       /* build header */
    NULL,                       /* push header */
    NULL,                       /* pop header */
    NULL,                       /* get_numa_id */
    NULL,                       /* set_multiq */

    NULL,                       /* send */
    NULL,                       /* send_wait */

    netdev_sim_set_etheraddr,
    netdev_sim_get_etheraddr,
    NULL,                       /* get_mtu */
    NULL,                       /* set_mtu */
    NULL,                       /* get_ifindex */
    netdev_sim_get_carrier,
    NULL,                       /* get_carrier_resets */
    NULL,                       /* get_miimon */
    netdev_sim_internal_get_stats,

    netdev_sim_get_features,    /* get_features */
    NULL,                       /* set_advertisements */

    NULL,                       /* set_policing */
    NULL,                       /* get_qos_types */
    NULL,                       /* get_qos_capabilities */
    NULL,                       /* get_qos */
    NULL,                       /* set_qos */
    NULL,                       /* get_queue */
    NULL,                       /* set_queue */
    NULL,                       /* delete_queue */
    NULL,                       /* get_queue_stats */
    NULL,                       /* queue_dump_start */
    NULL,                       /* queue_dump_next */
    NULL,                       /* queue_dump_done */
    NULL,                       /* dump_queue_stats */

    NULL,                       /* get_in4 */
    NULL,                       /* set_in4 */
    NULL,                       /* get_in6 */
    NULL,                       /* add_router */
    NULL,                       /* get_next_hop */
    NULL,                       /* get_status */
    NULL,                       /* arp_lookup */

    netdev_sim_update_flags,

    NULL,                       /* rxq_alloc */
    NULL,                       /* rxq_construct */
    NULL,                       /* rxq_destruct */
    NULL,                       /* rxq_dealloc */
    NULL,                       /* rxq_recv */
    NULL,                       /* rxq_wait */
    NULL,                       /* rxq_drain */
};

static const struct netdev_class sim_loopback_class = {
    "loopback",
    NULL,                       /* init */
    netdev_sim_run,
    NULL,                       /* wait */

    netdev_sim_alloc,
    netdev_sim_construct,
    netdev_sim_destruct,
    netdev_sim_dealloc,
    NULL,                       /* get_config */
    NULL,                       /* set_config */
    NULL,
    NULL,                       /* netdev_sim_loopback_set_hw_intf_config, */
    NULL,                       /* get_tunnel_config */
    NULL,                       /* build header */
    NULL,                       /* push header */
    NULL,                       /* pop header */
    NULL,                       /* get_numa_id */
    NULL,                       /* set_multiq */

    NULL,                       /* send */
    NULL,                       /* send_wait */

    netdev_sim_set_etheraddr,
    netdev_sim_get_etheraddr,
    NULL,                       /* get_mtu */
    NULL,                       /* set_mtu */
    NULL,                       /* get_ifindex */
    netdev_sim_get_carrier,
    NULL,                       /* get_carrier_resets */
    NULL,                       /* get_miimon */
    NULL,

    netdev_sim_get_features,    /* get_features */
    NULL,                       /* set_advertisements */

    NULL,                       /* set_policing */
    NULL,                       /* get_qos_types */
    NULL,                       /* get_qos_capabilities */
    NULL,                       /* get_qos */
    NULL,                       /* set_qos */
    NULL,                       /* get_queue */
    NULL,                       /* set_queue */
    NULL,                       /* delete_queue */
    NULL,                       /* get_queue_stats */
    NULL,                       /* queue_dump_start */
    NULL,                       /* queue_dump_next */
    NULL,                       /* queue_dump_done */
    NULL,                       /* dump_queue_stats */

    NULL,                       /* get_in4 */
    NULL,                       /* set_in4 */
    NULL,                       /* get_in6 */
    NULL,                       /* add_router */
    NULL,                       /* get_next_hop */
    NULL,                       /* get_status */
    NULL,                       /* arp_lookup */

    netdev_sim_update_flags,

    NULL,                       /* rxq_alloc */
    NULL,                       /* rxq_construct */
    NULL,                       /* rxq_destruct */
    NULL,                       /* rxq_dealloc */
    NULL,                       /* rxq_recv */
    NULL,                       /* rxq_wait */
    NULL,                       /* rxq_drain */
};

void
netdev_sim_register(void)
{
    netdev_register_provider(&sim_class);
    netdev_register_provider(&sim_internal_class);
    netdev_register_provider(&sim_loopback_class);
}
