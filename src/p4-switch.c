/*
 * Copyright (C) 2015 (Barefoot) Hewlett-Packard Development Company, L.P.
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

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <sched.h>
#include "openvswitch/vlog.h"
#include "p4-switch.h"

VLOG_DEFINE_THIS_MODULE(p4_sim_plugin);

void
p4_switch_init()
{
    /* TODO - handle multiple devices. Emulation device (p4-behavioral-model)
     * uses just one device (0)
     */
    int emulns_fd = -1;
    int swns_fd = -1;
    /* model runs in emulns while plugin runs in swns.
     * attach to emulns while initializing interface and communication with the model
     */
    if ((emulns_fd = open("/var/run/netns/emulns", O_RDONLY)) < 0) {
        VLOG_ERR("Cannot find emulns name space for the model - %s", strerror(errno));
    } else {
        if (setns(emulns_fd, 0) < 0) {
            VLOG_ERR("Failed to connect to netns for the model");
        } else {
            VLOG_INFO("============== Using emulns for the model");
        }
    }
    if ((swns_fd = open("/var/run/netns/swns", O_RDONLY)) < 0) {
        VLOG_ERR("Could not find swns - %s", strerror(errno));
    } else {
        VLOG_INFO("============== Found swns");
    }
    p4_pd_init();
    p4_pd_dc_init();
    p4_pd_dc_assign_device(0, "ipc:///tmp/bmv2-0-notifications.ipc", 10001);
    /* Initialize cpu interface between model and the plugin - this is done internally by api_init */
    switch_api_init(0, MAX_P4_SWITCH_PORTS+1);  /* add 1 port cpu port */
    start_switch_api_packet_driver();
    /* attach to swns for the rest of the processing */
    if (swns_fd >= 0) {
        if (setns(swns_fd, 0) < 0) {
            VLOG_ERR("Could not switch back to swns");
            return;
        }
        VLOG_INFO("Switched back to swns");
    }

    /* TODO install the cpu reason codes so that those packets are sent to CPU */
    /* Install L2 reason codes - STP, CDP, LLDP by default */
}
