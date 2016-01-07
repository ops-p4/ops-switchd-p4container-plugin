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
#include "switchapi/switch_base_types.h"

extern void start_switch_api_packet_driver(void);
void
p4_switch_init()
{
    p4_pd_init();
    p4_pd_dc_init();
    p4_pd_dc_assign_device(0, "ipc:///tmp/bmv2-0-notifications.ipc", 10001);
    /* init switchapi for device 0 and 256 ports - XXX redice ports to 64 for ops */
    switch_api_init(0, 256);
    start_switch_api_packet_driver();
    /* XXX install the cpu host interface and reason codes */
}
