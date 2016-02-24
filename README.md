OPS-SWITCHD-P4SWITCH-PLUGIN
============================

What is ops-switchd-p4switch-plugin ?
--------------------------------------
ops-switchd-p4switch-plugin is part of the P4 virtual switch based test
infrastructure of OpenSwitch.

This plugin provides a packet processing pipeline defined using P4 language 
and associated APIs (called switchapi) for run-time programming to the pipeline.
The P4 program and APIs are taken from open source software at github.com/p4lang/switch.git

The OpenSwitch simulation enables component and feature test in a pure software
simulation environment without a need for a physical network.
OpenSwitch controls and programs the forwarding plane device ("ASIC")
by using an ofproto provider class to manage L2 and L3 features, as well as a
netdev class to manage physical interfaces. The class functions are invoked
by the bridge software, and they abstract the forwarding device implementation.

This plugin provides the glue logic to connect netdev and ofproto class functions to
underlying switchapi functions to program the P4 pipeline.


What is the structure of the repository?
----------------------------------------
* `src` - contains c source files that provide netdev and ofproto class implementations and glue logic.
* `include` - contains c header files.
* `switch` - This is a git submodule that points to 'ops' branch of github.com/p4lang/switch.git
* `switch/p4src` - This contains P4 programs that define the pipeline
* `switch/switchapi` - This contains APIs to control and configure the P4 pipeline


What is the license?
--------------------
Apache 2.0 license. For more details refer to [COPYING](http://git.openswitch.net/cgit/openswitch/ops-switchd-p4switch-plugin/tree/COPYING)


How to make changes to P4 pipeline?
-----------------------------------
TBD

What other documents are available?
-----------------------------------
For the high level design of ops-switchd-p4plugin-plugin, refer to [DESIGN.md](http://www.openswitch.net/documents/dev/ops-switchd-p4plugin-plugin/tree/DESIGN.md)
For the current list of contributors and maintainers, refer to [AUTHORS.md](http://git.openswitch.net/cgit/openswitch/ops-switchd-p4plugin-plugin/tree/AUTHORS)

For general information about OpenSwitch project refer to http://www.openswitch.net.
