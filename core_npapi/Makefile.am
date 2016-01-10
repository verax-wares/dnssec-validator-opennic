
#ACLOCAL_AMFLAGS = -I $(top_srcdir)/m4

# Needed for EXTRA_DIST.
include $(top_srcdir)/core_js-ctypes/Makefile.core

NPAPI_PLUGIN_NAME_DNSSEC = DNSSECValidatorPlugin
NPAPI_PLUGIN_NAME_TLSA = TLSAValidatorPlugin

SHELL_CMD ?= bash

WORKDIRS = $(EMPTY)

# FIXME: Different suffixes on differemt systems.
if NPAPI_CORE
NPAPI_TARGETS = \
	fb-dnssec-stamp \
	fb-tlsa-stamp
endif

if STATIC_CORE
STATIC_LINKING = yes
else
STATIC_LINKING = no
endif

all: $(NPAPI_TARGETS)

fb-git-stamp:
	-rm -rf FireBreath
	git clone https://github.com/firebreath/FireBreath.git FireBreath
	cd FireBreath; git reset --hard 66af0df36be98e9fcf7ee196fe5c275e54752ae8; cd .. # 2014-06-24 17:48:14
	touch $@

fb-workdir-stamp: fb-git-stamp FireBreath
	cp -r FireBreath WDFireBreath
	touch $@

fb-projects-stamp: fb-workdir-stamp WDFireBreath
	-rm -rf WDFireBreath/projects
	$(INSTALL) -d WDFireBreath/projects
	cp -r $(top_srcdir)/plugin-source/* WDFireBreath/projects
	touch $@

INCLUDE_LOC = "$(abs_top_builddir)/core_npapi/WDFireBreath/projects/common"

fb-compile-stamp: fb-projects-stamp WDFireBreath/projects
	$(SHELL_CMD) $(PREP_FB_CMD) \
	    WDFireBreath/projects WDFireBreath/build \
	    -DSTATIC_LINKING="$(STATIC_LINKING)" \
	    -DLIBS_BUILT_DIR="$(abs_top_builddir)/static-libs/libs-built/" \
	    -DINCLUDE_LOC="$(INCLUDE_LOC)" -DLIBRARY_LOC="$(LIBRARY_LOC)" \
	    -DCMAKE_VERBOSE_MAKEFILE=1 \
	    -DCMAKE_C_FLAGS="$(LIB_CFLAGS)" -DCMAKE_CXX_FLAGS="$(LIB_CXXFLAGS)" \
	    $(ADDITIONAL_FB_FLAGS) \
	    -DCMAKE_BUILD_TYPE=MinSizeRel
	$(BUILD_FB_CMD)
	touch $@

fb-dnssec-stamp: fb-compile-stamp
	if [ -d WDFireBreath/build/projects/$(NPAPI_PLUGIN_NAME_DNSSEC)/Debug/np$(NPAPI_PLUGIN_NAME_DNSSEC).plugin ]; then \
		cp -R WDFireBreath/build/projects/$(NPAPI_PLUGIN_NAME_DNSSEC)/Debug/np$(NPAPI_PLUGIN_NAME_DNSSEC).plugin np$(NPAPI_PLUGIN_NAME_DNSSEC).plugin; \
		$(STRIP) np$(NPAPI_PLUGIN_NAME_DNSSEC).plugin/Contents/MacOS/np$(NPAPI_PLUGIN_NAME_DNSSEC); \
	elif [ -d WDFireBreath/build/projects/$(NPAPI_PLUGIN_NAME_DNSSEC)/np$(NPAPI_PLUGIN_NAME_DNSSEC).plugin ]; then \
		cp -R WDFireBreath/build/projects/$(NPAPI_PLUGIN_NAME_DNSSEC)/np$(NPAPI_PLUGIN_NAME_DNSSEC).plugin np$(NPAPI_PLUGIN_NAME_DNSSEC).plugin; \
		$(STRIP) np$(NPAPI_PLUGIN_NAME_DNSSEC).plugin/Contents/MacOS/np$(NPAPI_PLUGIN_NAME_DNSSEC); \
	elif [ -f WDFireBreath/build/bin/$(NPAPI_PLUGIN_NAME_DNSSEC)/np$(NPAPI_PLUGIN_NAME_DNSSEC)$(SO_SUFF) ]; then \
		$(INSTALL) -m 644 -s WDFireBreath/build/bin/$(NPAPI_PLUGIN_NAME_DNSSEC)/np$(NPAPI_PLUGIN_NAME_DNSSEC)$(SO_SUFF) np$(NPAPI_PLUGIN_NAME_DNSSEC)$(XPCOM_ABI_SUFF)$(SO_SUFF); \
	else \
		false; \
	fi
	touch $@

fb-tlsa-stamp: fb-compile-stamp
	if [ -d WDFireBreath/build/projects/$(NPAPI_PLUGIN_NAME_TLSA)/Debug/np$(NPAPI_PLUGIN_NAME_TLSA).plugin ]; then \
		cp -R WDFireBreath/build/projects/$(NPAPI_PLUGIN_NAME_TLSA)/Debug/np$(NPAPI_PLUGIN_NAME_TLSA).plugin np$(NPAPI_PLUGIN_NAME_TLSA).plugin; \
		$(STRIP) np$(NPAPI_PLUGIN_NAME_TLSA).plugin/Contents/MacOS/np$(NPAPI_PLUGIN_NAME_TLSA); \
	elif [ -d WDFireBreath/build/projects/$(NPAPI_PLUGIN_NAME_TLSA)/np$(NPAPI_PLUGIN_NAME_TLSA).plugin ]; then \
		cp -R WDFireBreath/build/projects/$(NPAPI_PLUGIN_NAME_TLSA)/np$(NPAPI_PLUGIN_NAME_TLSA).plugin np$(NPAPI_PLUGIN_NAME_TLSA).plugin; \
		$(STRIP) np$(NPAPI_PLUGIN_NAME_TLSA).plugin/Contents/MacOS/np$(NPAPI_PLUGIN_NAME_TLSA); \
	elif [ -f WDFireBreath/build/bin/$(NPAPI_PLUGIN_NAME_TLSA)/np$(NPAPI_PLUGIN_NAME_TLSA)$(SO_SUFF) ]; then \
		$(INSTALL) -m 644 -s WDFireBreath/build/bin/$(NPAPI_PLUGIN_NAME_TLSA)/np$(NPAPI_PLUGIN_NAME_TLSA)$(SO_SUFF) np$(NPAPI_PLUGIN_NAME_TLSA)$(XPCOM_ABI_SUFF)$(SO_SUFF); \
	else \
		false; \
	fi
	touch $@

CLEANFILES = \
	fb-workdir-stamp \
	fb-projects-stamp \
	fb-compile-stamp \
	$(NPAPI_TARGETS)

WORKDIRS += \
	WDFireBreath/projects \
	WDFireBreath \
	np$(NPAPI_PLUGIN_NAME_DNSSEC)$(XPCOM_ABI_SUFF)$(SO_SUFF) \
	np$(NPAPI_PLUGIN_NAME_DNSSEC).plugin \
	np$(NPAPI_PLUGIN_NAME_TLSA)$(XPCOM_ABI_SUFF)$(SO_SUFF) \
	np$(NPAPI_PLUGIN_NAME_TLSA).plugin

clean-local:
	for d in $(WORKDIRS); do \
		rm -rf $$d; \
	done

distclean-local:
	-rm -rf FireBreath
	-rm -rf fb-git-stamp

DNSSEC_CORE_SRCS_NPAPI = \
	$(top_srcdir)/plugin-source/DNSSECValidatorPlugin/Chrome/chromepackage/manifest.json \
	$(top_srcdir)/plugin-source/DNSSECValidatorPlugin/CMakeLists.txt \
	$(top_srcdir)/plugin-source/DNSSECValidatorPlugin/DNSSECValidatorPluginAPI.cpp \
	$(top_srcdir)/plugin-source/DNSSECValidatorPlugin/DNSSECValidatorPluginAPI.h \
	$(top_srcdir)/plugin-source/DNSSECValidatorPlugin/DNSSECValidatorPlugin.cpp \
	$(top_srcdir)/plugin-source/DNSSECValidatorPlugin/DNSSECValidatorPlugin.h \
	$(top_srcdir)/plugin-source/DNSSECValidatorPlugin/Factory.cpp \
	$(top_srcdir)/plugin-source/DNSSECValidatorPlugin/Mac/bundle_template/Info.plist \
	$(top_srcdir)/plugin-source/DNSSECValidatorPlugin/Mac/bundle_template/InfoPlist.strings \
	$(top_srcdir)/plugin-source/DNSSECValidatorPlugin/Mac/bundle_template/Localized.r \
	$(top_srcdir)/plugin-source/DNSSECValidatorPlugin/Mac/dmgdesign.applescript \
	$(top_srcdir)/plugin-source/DNSSECValidatorPlugin/Mac/dmg_template/.background/background.png \
	$(top_srcdir)/plugin-source/DNSSECValidatorPlugin/Mac/dmg_template/.background/PLACE_BACKGROUND_PICTURE_HERE.txt \
	$(top_srcdir)/plugin-source/DNSSECValidatorPlugin/Mac/dmg_template/README.txt \
	$(top_srcdir)/plugin-source/DNSSECValidatorPlugin/Mac/installer.cmake \
	$(top_srcdir)/plugin-source/DNSSECValidatorPlugin/Mac/projectDef.cmake \
	$(top_srcdir)/plugin-source/DNSSECValidatorPlugin/PluginConfig.cmake \
	$(top_srcdir)/plugin-source/DNSSECValidatorPlugin/Win/projectDef.cmake \
	$(top_srcdir)/plugin-source/DNSSECValidatorPlugin/Win/WiX/DNSSECValidatorPlugin.ddf \
	$(top_srcdir)/plugin-source/DNSSECValidatorPlugin/Win/WiX/DNSSECValidatorPlugin.inf \
	$(top_srcdir)/plugin-source/DNSSECValidatorPlugin/Win/WiX/DNSSECValidatorPluginInstaller.wxs \
	$(top_srcdir)/plugin-source/DNSSECValidatorPlugin/X11/projectDef.cmake \
	$(top_srcdir)/plugin-source/DNSSECValidatorPlugin/xpi/content/chrome.manifest \
	$(top_srcdir)/plugin-source/DNSSECValidatorPlugin/xpi/content/install.rdf

DANE_CORE_SRCS_NPAPI = \
	$(top_srcdir)/plugin-source/TLSAValidatorPlugin/Chrome/chromepackage/manifest.json \
	$(top_srcdir)/plugin-source/TLSAValidatorPlugin/CMakeLists.txt \
	$(top_srcdir)/plugin-source/TLSAValidatorPlugin/Factory.cpp \
	$(top_srcdir)/plugin-source/TLSAValidatorPlugin/Mac/bundle_template/Info.plist \
	$(top_srcdir)/plugin-source/TLSAValidatorPlugin/Mac/bundle_template/InfoPlist.strings \
	$(top_srcdir)/plugin-source/TLSAValidatorPlugin/Mac/bundle_template/Localized.r \
	$(top_srcdir)/plugin-source/TLSAValidatorPlugin/Mac/dmgdesign.applescript \
	$(top_srcdir)/plugin-source/TLSAValidatorPlugin/Mac/dmg_template/.background/background.png \
	$(top_srcdir)/plugin-source/TLSAValidatorPlugin/Mac/dmg_template/.background/PLACE_BACKGROUND_PICTURE_HERE.txt \
	$(top_srcdir)/plugin-source/TLSAValidatorPlugin/Mac/dmg_template/README.txt \
	$(top_srcdir)/plugin-source/TLSAValidatorPlugin/Mac/installer.cmake \
	$(top_srcdir)/plugin-source/TLSAValidatorPlugin/Mac/projectDef.cmake \
	$(top_srcdir)/plugin-source/TLSAValidatorPlugin/PluginConfig.cmake \
	$(top_srcdir)/plugin-source/TLSAValidatorPlugin/TLSAValidatorPluginAPI.cpp \
	$(top_srcdir)/plugin-source/TLSAValidatorPlugin/TLSAValidatorPluginAPI.h \
	$(top_srcdir)/plugin-source/TLSAValidatorPlugin/TLSAValidatorPlugin.cpp \
	$(top_srcdir)/plugin-source/TLSAValidatorPlugin/TLSAValidatorPlugin.h \
	$(top_srcdir)/plugin-source/TLSAValidatorPlugin/Win/projectDef.cmake \
	$(top_srcdir)/plugin-source/TLSAValidatorPlugin/Win/WiX/TLSAValidatorPlugin.ddf \
	$(top_srcdir)/plugin-source/TLSAValidatorPlugin/Win/WiX/TLSAValidatorPlugin.inf \
	$(top_srcdir)/plugin-source/TLSAValidatorPlugin/Win/WiX/TLSAValidatorPluginInstaller.wxs \
	$(top_srcdir)/plugin-source/TLSAValidatorPlugin/X11/projectDef.cmake \
	$(top_srcdir)/plugin-source/TLSAValidatorPlugin/xpi/content/chrome.manifest \
	$(top_srcdir)/plugin-source/TLSAValidatorPlugin/xpi/content/install.rdf

EXTRA_DIST = \
	$(DNSSEC_CORE_SRCS_EXTRA) \
	$(DANE_CORE_SRCS_EXTRA) \
	$(DNSSEC_CORE_SRCS_NPAPI) \
	$(DANE_CORE_SRCS_NPAPI)
