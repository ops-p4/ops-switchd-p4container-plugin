# Copyright (C) 2015 Hewlett Packard Enterprise Development LP
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
# This script is used as a virtual test setup. By using this script,
# or modifying it as required, developers can quickly build topologies
# and test their changes on their VMs.
# Pre-requisites:
# 1. Checkout the ops-vsi repo.
# 2. Run 'make devenv_ct_init'.
# 3. Export the docker image of the switch from your build directory.

# To run this file, we have to point to the native python inside the sandbox.
# ex: /usr/bin/sudo <SANDBOX>/build/tmp/sysroots/x86_64-linux/usr/bin/py.test -s dual_switch_test.py

import os
import time
from opsvsi.docker import *
from opsvsi.opsvsitest import *

class CustomTopology( Topo ):

    def build(self, hsts=2, sws=1, **_opts):
        '''Function to build the custom topology of two hosts and two switches'''
        self.hsts = hsts
        self.sws = sws
        #Add list of hosts
        for h in irange( 1, hsts):
            host = self.addHost('h%s' % h, ip = '172.17.0.%d/24' % h)

        #Add list of switches
        for s in irange(1, sws):
            switch = self.addSwitch('s%s' % s)

        #Add links between nodes based on custom topology
        for i in irange(1, sws):
            hostname = "h%s" % i
            swname = "s%s" % i
            self.addLink(hostname, swname, port1 = 1)

        #Connect the switches
        for i in irange(2, sws):
            self.addLink("s%s" % (i-1), "s%s" % i, port1 = 2, port2 = 2)

class twoSwitchTest( OpsVsiTest ):

  def setupNet(self):
    self.net = Mininet(topo=CustomTopology(hsts=2, sws=2,
                                           hopts=self.getHostOpts(),
                                           sopts=self.getSwitchOpts()),
                                           switch=VsiOpenSwitch,
                                           host=Host,
                                           link=OpsVsiLink, controller=None,
                                           build=True)

  def show_running_config(self):
      info("\n###### Show Running Config #####\n")
      for switch in self.net.switches:
          if isinstance(switch, VsiOpenSwitch):
              info("\n###### Switch %s ######\n" % switch.name)
              runconf = switch.cmdCLI("show running-config")
              info(runconf + "\n")

  def vlan_add(self, vlan = 10):
      info("\n###### Configuring Vlan ######\n")
      for switch in self.net.switches:
          if isinstance(switch, VsiOpenSwitch):
              switch.cmdCLI("configure terminal")
              switch.cmdCLI("vlan %s" % vlan)
              switch.cmdCLI("no shutdown")
              switch.cmdCLI("end")

  def config_interface(self, intf, mode, vlan):
      info("\n###### Configuring Interfaces ######\n")
      for switch in self.net.switches:
          if isinstance(switch, VsiOpenSwitch):
              switch.cmdCLI("configure terminal")
              switch.cmdCLI("interface %d" % intf)
              switch.cmdCLI("no routing")
              if mode == "access":
                  switch.cmdCLI("vlan access %s" % vlan)
              elif mode == "trunk":
                  switch.cmdCLI("vlan trunk allowed %s" % vlan)
                  switch.cmdCLI("vlan trunk native %s" % vlan)
              switch.cmdCLI("no shutdown")
              switch.cmdCLI("end")

  def mininet_ping_hosts(self):
    info("\n###### Ping Hosts #####\n")
    info("Sleep for 30 seconds for system to be up\n")
    time.sleep(30)
    hosts = self.net.hosts
    result = self.net.ping(hosts,30)

  def config_lag_interface(self, sw, lag_intf, mode, vlan, mem_intf_list):
    info("\n####### Configuring Lag Interface #######\n")
    switch = self.net.getNodeByName(sw)
    if isinstance(switch, VsiOpenSwitch):
        switch.cmdCLI("configure terminal")
        switch.cmdCLI("interface lag %d" % lag_intf)
        switch.cmdCLI("no routing")
        if mode == "access":
            switch.cmdCLI("vlan access %s" % vlan)
        elif mode == "trunk":
            switch.cmdCLI("vlan trunk allowed %s" % vlan)
            switch.cmdCLI("vlan trunk native %s" % vlan)
        switch.cmdCLI("no shutdown")
        switch.cmdCLI("exit")
        info("\n##### Configuring Lag Members ######\n")
        for intf in mem_intf_list:
            switch.cmdCLI("interface %d" % intf)
            switch.cmdCLI("lag %d" % lag_intf)
            switch.cmdCLI("no shutdown")
            switch.cmdCLI("end")

  def mininet_cli(self):
    CLI(self.net)

class Test_example:

  def setup_class(self):
    # Create the Mininet topology based on mininet.
    info("##### Create Topology #####\n")
    Test_example.test = twoSwitchTest()

  def test_vlan_add(self):
    info("##### Configure Vlan #####\n")
    self.test.vlan_add(vlan=100)

  def test_config_interface(self):
    info("##### Configure Host Interfaces - Access Mode #####\n")
    self.test.config_interface(intf=1,mode="access",vlan=100)
    info("##### Configure Switch Interfaces - Trunk Mode #####\n")
    self.test.config_interface(intf=2,mode="trunk",vlan=100)

  def test_show_run_1(self):
    self.test.show_running_config()

  def test_mininet_ping_hosts1(self):
    info("##### Ping Hosts 1 #####\n")
    self.test.mininet_ping_hosts()

  # Test for slow routing between directly connected hosts
  #def test_mininet_cli(self):
  #  self.test.mininet_cli()

  def test_config_lag_interface(self):
    info("##### Configure Lag Interface - Trunk Mode #####\n")
    self.test.config_lag_interface(sw="s1", lag_intf=1,\
                                   mode="trunk", vlan="100",\
                                   mem_intf_list=[2])

  def test_show_run_2(self):
    self.test.show_running_config()

  def test_mininet_ping_hosts2(self):
    info("##### Ping Hosts 2 #####\n")
    self.test.mininet_ping_hosts()

  def teardown_class(cls):
    # Stop the Docker containers, and
    # mininet topology
    Test_example.test.net.stop()

  def __del__(self):
    del self.test
