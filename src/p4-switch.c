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

#include "p4-switch.h"

void
p4_switch_init()
{
    /* TODO - handle multiple devices. Emulation device (p4-behavioral-model)
     * uses just one device (0)
     */
#if 1
    p4_pd_init();
    p4_pd_dc_init();
    p4_pd_dc_assign_device(0, "ipc:///tmp/bmv2-0-notifications.ipc", 10001);
    /* init switchapi for device 0 and 256 ports - XXX redice ports to 64 for ops */
    /* Initialize cpu interface between model and the plugin - this is done internally by api_init */
    switch_api_init(0, 256);
    start_switch_api_packet_driver();

    /* TODO install the cpu reason codes so that those packets are sent to CPU */
    /* Install L2 reason codes - STP, CDP, LLDP by default */
#endif
}
