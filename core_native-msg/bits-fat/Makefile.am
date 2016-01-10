
#ACLOCAL_AMFLAGS = -I $(top_srcdir)/m4

if BUILD_FAT_OSX
all: dnssec-plug dane-plug
endif

CLEANFILES = \
	dnssec-plug \
	dane-plug

dnssec-plug: $(abs_top_builddir)/core_native-msg/bits-32/dnssec-plug $(abs_top_builddir)/core_native-msg/bits-64/dnssec-plug
	lipo -create $^ -output $@
	lipo -info $@
	otool -L $@

dane-plug: $(abs_top_builddir)/core_native-msg/bits-32/dane-plug $(abs_top_builddir)/core_native-msg/bits-64/dane-plug
	lipo -create $^ -output $@
	lipo -info $@
	otool -L $@
