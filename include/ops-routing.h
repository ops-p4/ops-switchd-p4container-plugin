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

#ifndef __OPS_ROUTING_H__
#define __OPS_ROUTING_H__ 1

#include "ofproto/ofproto-provider.h"
#include "p4-switch.h"

#define OPS_ROUTE_HASH_MAXSIZE 64

#define MAX_NEXTHOPS_PER_ROUTE 16

struct ops_route {
    struct hmap_node node;
    switch_handle_t vrf_handle;
    char *prefix;
    bool is_ipv6_addr;
    int n_nexthops;
    struct hmap nexthops;
    switch_handle_t handle;
};

struct ops_nexthop {
    struct hmap_node node;
    char *id;
    switch_handle_t nhop_handle;
};

#endif /* __OPS_ROUTING_H__ */
