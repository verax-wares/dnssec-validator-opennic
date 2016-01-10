
#ACLOCAL_AMFLAGS = -I $(top_srcdir)/m4

AM_CPPFLAGS = \
	-include $(top_srcdir)/plugin-source/config.h \
	@CORE_CPPFLAGS@ \
	@CORE_CPPFLAGS_32@ \
	-I$(top_srcdir)/plugin-source/common/

AM_CFLAGS = \
	@CORE_CFLAGS_32@

USED_CORE_LDFLAGS = @CORE_LDFLAGS_32@

LIBS_BUILT = libs-built-32

include ../Makefile.core

if BUILD_32
include ../Makefile.libs
endif
