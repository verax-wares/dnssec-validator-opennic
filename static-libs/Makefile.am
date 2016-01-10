
#ACLOCAL_AMFLAGS = -I $(top_srcdir)/m4

if STATIC_CORE

if BUILD_32
all: built-unbound-32-stamp
endif

if BUILD_64
all: built-unbound-64-stamp
endif

libs-archives-stamp:
	-rm -rf libs-archives
	git clone https://gitlab.labs.nic.cz/mstraka/dnssec-libs.git libs-archives
	cd libs-archives; git checkout 3481ae7a05b277809f2e052c70659911e28f437f; cd ..
	touch $@

libs-srcs-32-stamp: libs-archives-stamp
	-rm -rf libs-srcs-32
	$(INSTALL) -d libs-srcs-32
	touch $@

libs-srcs-64-stamp: libs-archives-stamp
	-rm -rf libs-srcs-64
	$(INSTALL) -d libs-srcs-64
	touch $@

srcs-openssl-32-stamp: libs-srcs-32-stamp
	-rm -rf libs-srcs-32/openssl*
	cd libs-srcs-32; tar -xzf ../libs-archives/openssl*.tar.gz; mv openssl-* openssl; cd ..
	touch $@

srcs-openssl-64-stamp: libs-srcs-64-stamp
	-rm -rf libs-srcs-64/openssl*
	cd libs-srcs-64; tar -xzf ../libs-archives/openssl*.tar.gz; mv openssl-* openssl; cd ..
	touch $@

srcs-ldns-32-stamp: libs-srcs-32-stamp
	-rm -rf libs-srcs-32/ldns*
	cd libs-srcs-32; tar -xzf ../libs-archives/ldns*.tar.gz; mv ldns-* ldns; cd ..
	touch $@

srcs-ldns-64-stamp: libs-srcs-64-stamp
	-rm -rf libs-srcs-64/ldns*
	cd libs-srcs-64; tar -xzf ../libs-archives/ldns*.tar.gz; mv ldns-* ldns; cd ..
	touch $@

srcs-unbound-32-stamp: libs-srcs-32-stamp
	-rm -rf libs-srcs-32/unbound*
	cd libs-srcs-32; tar -xzf ../libs-archives/unbound*.tar.gz; mv unbound-* unbound; cd ..
	touch $@

srcs-unbound-64-stamp: libs-srcs-64-stamp
	-rm -rf libs-srcs-64/unbound*
	cd libs-srcs-64; tar -xzf ../libs-archives/unbound*.tar.gz; mv unbound-* unbound; cd ..
	touch $@

libs-built-32-stamp:
	-rm -rf libs-built-32
	$(INSTALL) -d libs-built-32
	touch $@

libs-built-64-stamp:
	-rm -rf libs-built-64
	$(INSTALL) -d libs-built-64
	touch $@

built-openssl-32-stamp: srcs-openssl-32-stamp libs-built-32-stamp
	-rm -rf libs-built-32/openssl
	$(INSTALL) -d libs-built-32/openssl
	(cd libs-srcs-32/openssl && $(SED) -e 's/\(^"BSD-[^"]*",[^g]*\)gcc\(.*\$\)/\1cc\2/g' < Configure > ConfigureBSD || cp Configure ConfigureBSD; chmod +x ConfigureBSD)
	(cd libs-srcs-32/openssl && ./ConfigureBSD no-shared no-krb5 --prefix="$(abs_builddir)/libs-built-32/openssl" $(OPENSSL_ARGS_32) $(CROSSCOMPILE_OPENSSL_FLAGS) && $(MAKE) -j1 && $(MAKE) -j1 install_sw && $(MAKE) clean)
	touch $@

built-openssl-64-stamp: srcs-openssl-64-stamp libs-built-64-stamp
	-rm -rf libs-built-64/openssl
	$(INSTALL) -d libs-built-64/openssl
	(cd libs-srcs-64/openssl && $(SED) -e 's/\(^"BSD-[^"]*",[^g]*\)gcc\(.*\$\)/\1cc\2/g' < Configure > ConfigureBSD || cp Configure ConfigureBSD; chmod +x ConfigureBSD)
	(cd libs-srcs-64/openssl && ./ConfigureBSD no-shared no-krb5 --prefix="$(abs_builddir)/libs-built-64/openssl" $(OPENSSL_ARGS_64) $(CROSSCOMPILE_OPENSSL_FLAGS) && $(MAKE) -j1 && $(MAKE) -j1 install_sw && $(MAKE) clean)
	touch $@

if MINGW_BUILD
COPY_HEADERS_CMD_32 = \
	(cd libs-srcs-32/ldns && \
	$(INSTALL) -d $(abs_builddir)/libs-built-32/windows/x86/ldns && \
	$(INSTALL) -m 644 ldns/config.h $(abs_builddir)/libs-built-32/windows/x86/ldns/config.h && \
	$(INSTALL) -m 644 ldns/net.h $(abs_builddir)/libs-built-32/windows/x86/ldns/net.h)
endif

built-ldns-32-stamp: srcs-ldns-32-stamp libs-built-32-stamp built-openssl-32-stamp
	-rm -rf libs-built-32/ldns
	$(INSTALL) -d libs-built-32/ldns
	(cd libs-srcs-32/ldns && $(CROSSCOMPILE_PREPARATION_EXPORTS) \
	    CFLAGS="$(LIB_CFLAGS_32)" ./configure --disable-shared $(CROSSCOMPILE_HOST_FLAGS) \
	    --with-ssl="$(abs_builddir)/libs-built-32/openssl" \
	    --disable-ldns-config --without-pyldnsx \
	    --with-pic --prefix="$(abs_builddir)/libs-built-32/ldns" $(CONFIGURE_ARGS) && \
	    CFLAGS="$(CFLAGS)" $(MAKE) && $(MAKE) install && \
	    $(MAKE) clean)
	$(COPY_HEADERS_CMD_32)
	touch $@

built-ldns-64-stamp: srcs-ldns-64-stamp libs-built-64-stamp built-openssl-64-stamp
	-rm -rf libs-built-64/ldns
	$(INSTALL) -d libs-built-64/ldns
	(cd libs-srcs-64/ldns && $(CROSSCOMPILE_PREPARATION_EXPORTS) \
	    CFLAGS="$(LIB_CFLAGS_64)" ./configure --disable-shared $(CROSSCOMPILE_HOST_FLAGS) \
	    --with-ssl="$(abs_builddir)/libs-built-64/openssl" \
	    --disable-ldns-config --without-pyldnsx \
	    --with-pic --prefix="$(abs_builddir)/libs-built-64/ldns" $(CONFIGURE_ARGS) && \
	    CFLAGS="$(CFLAGS)" $(MAKE) && $(MAKE) install && \
	    $(MAKE) clean)
	$(COPY_HEADERS_CMD_64)
	touch $@

built-unbound-32-stamp: srcs-unbound-32-stamp libs-built-32-stamp built-openssl-32-stamp built-ldns-32-stamp
	-rm -rf libs-built-32/unbound
	$(INSTALL) -d libs-built-32/unbound
	(cd libs-srcs-32/unbound && $(CROSSCOMPILE_PREPARATION_EXPORTS) \
	    CFLAGS="$(LIB_CFLAGS_32)" ./configure --disable-shared $(CROSSCOMPILE_HOST_FLAGS) \
	    --with-ssl="$(abs_builddir)/libs-built-32/openssl" \
	    --with-ldns="$(abs_builddir)/libs-built-32/ldns" --without-libevent \
	    --with-pic --prefix="$(abs_builddir)/libs-built-32/unbound" $(CONFIGURE_ARGS) \
	    --with-libunbound-only && \
	    CFLAGS="$(CFLAGS)" $(MAKE) && $(MAKE) install && \
	    $(MAKE) clean)
	touch $@

built-unbound-64-stamp: srcs-unbound-64-stamp libs-built-64-stamp built-openssl-64-stamp built-ldns-64-stamp
	-rm -rf libs-built-64/unbound
	$(INSTALL) -d libs-built-64/unbound
	(cd libs-srcs-64/unbound && $(CROSSCOMPILE_PREPARATION_EXPORTS) \
	    CFLAGS="$(LIB_CFLAGS_64)" ./configure --disable-shared $(CROSSCOMPILE_HOST_FLAGS) \
	    --with-ssl="$(abs_builddir)/libs-built-64/openssl" \
	    --with-ldns="$(abs_builddir)/libs-built-64/ldns" --without-libevent \
	    --with-pic --prefix="$(abs_builddir)/libs-built-64/unbound" $(CONFIGURE_ARGS) \
	    --with-libunbound-only && \
	    CFLAGS="$(CFLAGS)" $(MAKE) && $(MAKE) install && \
	    $(MAKE) clean)
	touch $@

CLEANFILES = \
	libs-srcs-32-stamp \
	libs-srcs-64-stamp \
	srcs-openssl-32-stamp \
	srcs-openssl-64-stamp \
	srcs-ldns-32-stamp \
	srcs-ldns-64-stamp \
	srcs-unbound-32-stamp \
	srcs-unbound-64-stamp \
	libs-built-32-stamp \
	libs-built-64-stamp \
	built-openssl-32-stamp \
	built-openssl-64-stamp \
	built-ldns-32-stamp \
	built-ldns-64-stamp \
	built-unbound-32-stamp \
	built-unbound-64-stamp

DISTCLEANFILES = \
	libs-archives-stamp

clean-local:
	-rm -rf libs-srcs-* libs-built-*

distclean-local:
	-rm -rf libs-archives

endif
