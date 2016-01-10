
#ACLOCAL_AMFLAGS = -I $(top_srcdir)/m4


TARGETS = $(EMPTY)
WORKDIRS = $(EMPTY)
BUILT_SOURCES = $(EMPTY)
CLEANFILES = $(EMPTY)
DIST_FILES = $(EMPTY)


do_subst = sed \
	-e 's,[@]PACKAGE[@],$(PACKAGE),g' \
	-e 's,[@]OS_TARGET[@],$(OS_TARGET),g' \
	-e 's,[@]VERSION[@],$(PACKAGE_VERSION),g' \
	-e 's,[@]PACKAGE_VERSION[@],$(PACKAGE_VERSION),g' \
	-e 's,[@]XPCOM_ABI_SUFF[@],$(XPCOM_ABI_SUFF),g'


include Makefile.content
include Makefile.mozz
include Makefile.cr_dnssec
include Makefile.cr_tlsa
include Makefile.saf


if EXTPKG_CR_NM
TARGETS += \
	install_chrome_variables.sh

install_chrome_variables.sh: install_chrome_variables.sh.in Makefile
	$(do_subst) < $< > $@
endif


EXTRA_DIST = \
	install_chrome_variables.sh.in \
	Makefile.content \
	Makefile.mozz \
	Makefile.cr_dnssec \
	Makefile.cr_tlsa \
	Makefile.saf \
	$(DIST_FILES)


clean-local:
	for d in $(WORKDIRS); do \
		rm -rf $$d; \
	done


all: $(TARGETS)
