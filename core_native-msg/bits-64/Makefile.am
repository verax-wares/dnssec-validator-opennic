
#ACLOCAL_AMFLAGS = -I $(top_srcdir)/m4

AM_CPPFLAGS = \
	-include $(top_srcdir)/plugin-source/config.h \
	@CORE_CPPFLAGS@ \
	@CORE_CPPFLAGS_64@ \
	-I$(top_srcdir)/plugin-source/common/

AM_CFLAGS = \
	@CORE_CFLAGS_64@

AM_OBJCFLAGS = \
	@CORE_OBJCFLAGS_64@

LIBS_BUILT = libs-built-64

include $(top_srcdir)/core_js-ctypes/Makefile.core

if BUILD_64
include ../Makefile.apps
endif
