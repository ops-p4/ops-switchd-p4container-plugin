ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I m4

SUBDIRS = switch/p4src switch/switchapi

prog_CFLAGS = $(AM_CFLAGS)

PFX ?=

OVSCOMMON_INCLUDE_DIRS = $(PFX)/$(includedir)/ovs
OVSCOMMON_LIB = $(PFX)/$(libdir)/libovscommon.la

p4_plugin_files = \
src/netdev-sim.c \
src/ofproto-sim-provider.c \
src/p4-switch.c \
src/sim-plugins.c

noinst_LTLIBRARIES = lib_ovs_p4_sim_plugin_interface.la
lib_ovs_p4_sim_plugin_interface_la_SOURCES = $(p4_plugin_files)
lib_ovs_p4_sim_plugin_interface_la_CFLAGS = -I $(srcdir)/include
lib_ovs_p4_sim_plugin_interface_la_CFLAGS += -I ${OVSCOMMON_INCLUDE_DIRS}
lib_ovs_p4_sim_plugin_interface_la_CFLAGS += -I $(srcdir)/switch/switchapi/inc
lib_ovs_p4_sim_plugin_interface_la_CFLAGS += -I $(srcdir)/switch/switchapi/third-party/tommyds/include
lib_ovs_p4_sim_plugin_interface_la_CFLAGS += -I $(srcdir)/switch/p4src/includes
lib_ovs_p4_sim_plugin_interface_la_CFLAGS += -I $(srcdir)/switch/p4src/bmv2_p4_pd
lib_ovs_p4_sim_plugin_interface_la_CFLAGS += -I $(PFX)/$(includedir)/pdfixed

lib_ovs_p4_sim_plugin_interface_la_CFLAGS += -std=gnu99 -D BMV2

SWITCHAPI_DIR = $(srcdir)/switch/switchapi
SWITCHAPI_LIB := $(SWITCHAPI_DIR)/libswitchapi.la

SWITCHP4_DIR = $(srcdir)/switch/p4src
SWITCHP4_PD_LIB := $(SWITCHP4_DIR)/libbmv2pd.la

BUILT_SOURCES = $(datadir)/switch_bmv2.json

$(SWITCHP4_PD_LIB):
	@$(MAKE) -C $(SWITCHP4_DIR) PFX=$(PFX)

$(BUILT_SOURCES) : $(SWITCHP4_PD_LIB)
	@$(MAKE) -C $(SWITCHAPI_DIR) PFX=$(PFX)

# need to find a way to link all libs together into a single .so
# catch (for not using LIBADD) is the dependency
lib_LTLIBRARIES = lib_ovs_p4_sim_plugin.la

BMV2PD_EXTRA_LIBS := $(PFX)/$(libdir)/libpdfixed.la
BMV2PD_EXTRA_LIBS += $(PFX)/$(libdir)/libpdfixedthrift.la
BMV2PD_EXTRA_LIBS += $(PFX)/$(libdir)/libbmthrift.la
BMV2PD_EXTRA_LIBS += $(PFX)/$(libdir)/libsswitch.la

lib_ovs_p4_sim_plugin_la_SOURCES =
lib_ovs_p4_sim_plugin_la_LIBADD = $(noinst_LTLIBRARIES) $(SWITCHAPI_LIB) $(SWITCHP4_PD_LIB) $(BMV2PD_EXTRA_LIBS) $(OVSCOMMON_LIB)

CLEANFILES = $(lib_LTLIBRARIES) $(BUILT_SOURCES)
.PHONY: $(SWITCHP4_PD_LIB)
