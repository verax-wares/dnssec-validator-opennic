
#ACLOCAL_AMFLAGS = -I $(top_srcdir)/m4

if BUILD_FAT_OSX
all: libDNSSECcore$(SO_SUFF) libDANEcore$(SO_SUFF)
endif

CLEANFILES = \
	libDNSSECcore$(SO_SUFF) \
	libDANEcore$(SO_SUFF)

libDNSSECcore$(SO_SUFF): $(abs_top_builddir)/core_js-ctypes/bits-32/libDNSSECcore$(SO_SUFF) $(abs_top_builddir)/core_js-ctypes/bits-64/libDNSSECcore$(SO_SUFF)
	lipo -create $^ -output $@
	lipo -info $@
	otool -L $@

libDANEcore$(SO_SUFF): $(abs_top_builddir)/core_js-ctypes/bits-32/libDANEcore$(SO_SUFF) $(abs_top_builddir)/core_js-ctypes/bits-64/libDANEcore$(SO_SUFF)
	lipo -create $^ -output $@
	lipo -info $@
	otool -L $@
