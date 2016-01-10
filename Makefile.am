## Process this file with automake to produce Makefile.in

# Scan for additional macro definitions.
#ACLOCAL_AMFLAGS = -I $(top_srcdir)/m4

SUBDIRS = \
	static-libs \
	core_js-ctypes \
	core_native-msg \
	core_npapi \
	add-on

DOCUMENTS = \
	Doc/DANE-TLSA_Validator_2.x-specification.odt \
	Doc/DNSSEC_Validator_2.0-specification.odt \
	Doc/DNSSEC_Validator_2.0-specification.pdf \
	Doc/DNSSEC_Validator_2.0_validation_flowchart.dia \
	Doc/DNSSEC_Validator_2.0_validation_flowchart.png

EXTRA_DIST = \
	$(DOCUMENTS) \
	Build \
	CHANGELOG \
	MSVS-build.bat \
	authors.info \
	autogen.sh \
	build_osx_fat_autotools.sh \
	scripts/install_chrome_add_payload.sh \
	scripts/install_chrome_stub.sh \
	install_osx_safari_add_payload.sh \
	install_osx_safari_stub.sh
