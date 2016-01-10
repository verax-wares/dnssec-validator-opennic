
#ACLOCAL_AMFLAGS = -I $(top_srcdir)/m4

AM_CPPFLAGS = \
	-include $(top_srcdir)/plugin-source/config.h \
	@CORE_CPPFLAGS@ \
	@CORE_CPPFLAGS_64@ \
	-I$(top_srcdir)/plugin-source/common/

AM_CFLAGS = \
	@CORE_CFLAGS_64@

USED_CORE_LDFLAGS = @CORE_LDFLAGS_64@

LIBS_BUILT = libs-built-64

include ../Makefile.core

if BUILD_64
include ../Makefile.libs
endif
