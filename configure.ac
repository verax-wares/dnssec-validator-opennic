#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.60])
AC_INIT([dnssec-validator], [2.2.0.2], [dnssec-validator-users@lists.nic.cz])
AC_CONFIG_SRCDIR([plugin-source/common/common.h])
AC_CONFIG_HEADERS([plugin-source/config.h])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([1.10 foreign dist-xz tar-ustar -Wall])
# The tar-ustar option is required to be able to store long file names when
# make dist is run.

AC_CANONICAL_HOST
#AC_CANONICAL_TARGET
#AC_MSG_ERROR([$host_os $target_os $host_cpu $target_cpu $host_alias $target_alias])

sinclude(ax_pthread.m4)
sinclude(ld-version-script.m4)

# Config header file prefix
AH_TOP([#ifndef _CONFIG_H_])
AH_TOP([#define _CONFIG_H_])
# Config header file suffix
AH_BOTTOM([#endif /* !_CONFIG_H_ */])

# Flags passed by the user
PASSED_CPPFLAGS="$CPPFLAGS"
PASSED_CFLAGS="$CFLAGS"
PASSED_CXXFLAGS="$CXXFLAGS"
PASSED_OBJCFLAGS="$OBJCFLAGS"
PASSED_LDFLAGS="$LDFLAGS"
#PASSED_LIBS="$LIBS"
# Default flags
CORE_CPPFLAGS="$PASSED_CPPFLAGS"
CORE_CFLAGS="$PASSED_CFLAGS -Wall -Wextra -pedantic -std=c99 -Wno-variadic-macros"
CORE_CXXFLAGS="$PASSED_CXXFLAGS -Wall -Wextra -pedantic -std=c++98 -Wno-variadic-macros -fno-exceptions -fno-rtti -fno-common"
CORE_OBJCFLAGS="$PASSED_OBJCFLAGS -Wall -Wextra -pedantic"
CORE_LDFLAGS="$PASSED_LDFLAGS"
CORE_LIBS=""

# Debugging
AC_MSG_CHECKING([whether to enable debugging])
AC_ARG_ENABLE([debug],
  AS_HELP_STRING([--enable-debug], [Enable debugging.]))
AS_IF([test "x$enable_debug" = "xyes"], [
  AC_MSG_RESULT([yes])
  dnl C preprocessor
  AC_DEFINE(DEBUG, 1, [Define to 1 if debugging functionality desired.])
  CORE_CFLAGS="${CORE_CFLAGS} -g -O0 -fno-omit-frame-pointer -fstack-protector -Wuninitialized"
  CORE_CXXFLAG="${CORE_CXXFLAGS} -g -O0 -fno-omit-frame-pointer -Wuninitialized"
  CORE_OBJCFLAGS="${CORE_OBJCFLAGS} -g -O0"
], [
  AC_MSG_RESULT([no])
  dnl C preprocessor
  AC_DEFINE(NDEBUG, 1, [Define to 1 if no debugging functionality desired.])
  CORE_CFLAGS="${CORE_CFLAGS} -O3"
  CORE_CXXFLAGS="${CORE_CXXFLAGS} -O3"
  CORE_OBJCFLAGS="${CORE_OBJCFLAGS} -O3"
])
AC_SUBST(CORE_CPPFLAGS)
AC_SUBST(CORE_CFLAGS)
AC_SUBST(CORE_CXXFLAGS)
AC_SUBST(CORE_OBJCFLAGS)
AC_SUBST(CORE_LDFLAGS)
AC_SUBST(CORE_LIBS)

# Checks for programs.
AM_PROG_AR
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_CXX
AC_PROG_INSTALL
AC_PROG_LIBTOOL
AC_PROG_MAKE_SET # Set make command.
AC_PROG_MKDIR_P # mkdir -p
AC_PROG_OBJC # OS X only.
AC_PROG_SED

AC_CHECK_PROG(UNZIP,unzip,yes)
AS_IF([test "x${UNZIP}" = "xyes"], [
], [
  AC_MSG_ERROR([Program unzip not found.])
])
AC_CHECK_PROG(ZIP,zip,yes)
AS_IF([test "x${ZIP}" = "xyes"], [
], [
  AC_MSG_ERROR([Program zip not found.])
])

# Checks for stuff needed to build libraries.
AC_PROG_LIBTOOL
LT_INIT
LT_PATH_LD
LT_PATH_NM

# FreeBSD keeps using -retain-symbols-file instead of -version-script when
# linking js-ctypes core libraries.
# The -retain-symbols-file seems not to work well when linking static libraries
# into a shared object target.
gl_LD_VERSION_SCRIPT

# The following host is known to produce binaries working on Windows XP.
# --host=i586-mingw32msvc
# (Linux Mint Cinnamon 17 64-bit)

# Set Mozilla OS_TARGET
# https://developer.mozilla.org/en-US/docs/OS_TARGET
AS_CASE([$host_os],
  [darwin*], [OS_TARGET=Darwin],
  [linux*], [OS_TARGET=Linux],
  [freebsd*], [OS_TARGET=FreeBSD],
  [dragonfly*], [OS_TARGET=DragonFly],
  [mingw*], [OS_TARGET=WINNT]
)
AC_SUBST(OS_TARGET)

# Set Mozilla XPCOM_ABI
# https://developer.mozilla.org/en-US/docs/XPCOM_ABI
AS_CASE([$host_cpu],
  [i[[3456]]86], [XPCOM_ABI=x86],
  [amd64|x86_64], [XPCOM_ABI=x86_64],
)
#AC_SUBST(XPCOM_ABI)

# Set shared library prefixes and suffixes.
AS_CASE([$host_os],
  [darwin*], [
    SO_PREF='lib'
    SO_SUFF='.dylib'
    EXE_SUFF=''
  ],
  [mingw*], [
    SO_PREF=''
    SO_SUFF='.dll'
    EXE_SUFF='.exe'
  ],
  [
    SO_PREF='lib'
    SO_SUFF='.so'
    EXE_SUFF=''
  ]
)
AC_SUBST(SO_PREF)
AC_SUBST(SO_SUFF)
AC_SUBST(EXE_SUFF)


###############################################################################
# Installation location.
###############################################################################

AC_ARG_VAR(MF_JC_INSTDIRS, [Colon-separated list of locations of the \
system-wide browser-specific (Firefox/Iceweasel) directories where the \
js-ctypes extension should be installed.])
MF_JC_INSTDIRS=`echo "${MF_JC_INSTDIRS}" | ${SED} -e 's/:/ /g'`
for dir in ${MF_JC_INSTDIRS}; do
  if [[ ! -d "$dir" ]]; then
    AC_MSG_ERROR([The directory '$dir' does not exist.])
  fi
done


###############################################################################
# Force XPCOM_ABI on Intel.
###############################################################################

XPCOM_ABI_SUFF_32='-x86'
XPCOM_ABI_SUFF_64='-x86_64'

BITS=auto
AC_ARG_WITH([force-abi],
  [AS_HELP_STRING([--with-force-abi=[auto|x86|x86_64|fat]], [Architecture bits, 'auto' is default.])],
  [
    AS_CASE([$XPCOM_ABI],
      [x86|x86_64], [
        # Values are defined in dane-plug.c .
        AS_CASE([$withval],
          [auto], [
            BITS=auto
            # Don't change detected XPCOM_ABI.
          ],
          [x86], [
            BITS=32
            XPCOM_ABI=$withval
          ],
          [x86_64], [
            BITS=64
            XPCOM_ABI=$withval
          ],
          [fat], [
            BITS=fat
            XPCOM_ABI='' # Unset, as the library contains more
          ],
          [AC_MSG_WARN(["Unknown force bits option '$withval'."])]
        )
      ],
      [
        AC_MSG_ERROR([Sorry you are not allowed to force $withval on $XPCOM_ABI hosts.])
      ]
    )
  ])
AS_IF([test "x${BITS}" = "xauto"], [
  AS_CASE([$XPCOM_ABI],
    [x86], [BITS=32],
    [x86_64], [BITS=64],
    [AC_MSG_ERROR([Could not determine architecture.])]
  )
])

AS_IF([test "x${XPCOM_ABI}" != "x"], [
  #XPCOM_ABI_SUFF="-${XPCOM_ABI}"
  XPCOM_ABI_SUFF=''
])
AC_SUBST(XPCOM_ABI_SUFF)
AC_SUBST(XPCOM_ABI_SUFF_32)
AC_SUBST(XPCOM_ABI_SUFF_64)


###############################################################################
# Core dependencies.
###############################################################################

# OS-specific FireBreath build settings.
PREP_FB_CMD="./WDFireBreath/prepmake.sh"
ADDITIONAL_FB_FLAGS=""
BUILD_FB_CMD='$(MAKE) -C WDFireBreath/build'
AS_CASE([$host_os],
  [darwin*], [
    PREP_FB_CMD="./WDFireBreath/prepmac.sh"
    BUILD_FB_CMD='cd WDFireBreath/build && xcodebuild && cd ../..'
  ]
)
AC_SUBST(PREP_FB_CMD)
AC_SUBST(ADDITIONAL_FB_FLAGS)
AC_SUBST(BUILD_FB_CMD)

# Check whether to build and statically link core library dependencies -- default off.
AC_MSG_CHECKING([Whether to build core with statically linked libraries.])
AC_ARG_ENABLE([static-linking],
  AS_HELP_STRING([--enable-static-linking], [Enable statically linked core.]))
AS_IF([test "x$enable_static_linking" = "xyes"], [
  AC_MSG_RESULT([yes]) # Static linking.

  # FIXME: get the CONFIGURE_FLAGS from the environment.

  CORE_CPPFLAGS_32=''
  CORE_CPPFLAGS_32="${CORE_CPPFLAGS_32}"' -I$(top_srcdir)/static-libs/libs-built-32/openssl/include'
  CORE_CPPFLAGS_32="${CORE_CPPFLAGS_32}"' -I$(top_srcdir)/static-libs/libs-built-32/ldns/include'
  CORE_CPPFLAGS_32="${CORE_CPPFLAGS_32}"' -I$(top_srcdir)/static-libs/libs-built-32/unbound/include'
  CORE_CPPFLAGS_64=''
  CORE_CPPFLAGS_64="${CORE_CPPFLAGS_64}"' -I$(top_srcdir)/static-libs/libs-built-64/openssl/include'
  CORE_CPPFLAGS_64="${CORE_CPPFLAGS_64}"' -I$(top_srcdir)/static-libs/libs-built-64/ldns/include'
  CORE_CPPFLAGS_64="${CORE_CPPFLAGS_64}"' -I$(top_srcdir)/static-libs/libs-built-64/unbound/include'

  AM_CONDITIONAL([BUILD_32], [test "x${BITS}" = "x32" || test "x${BITS}" = "xfat"])
  AM_CONDITIONAL([BUILD_64], [test "x${BITS}" = "x64" || test "x${BITS}" = "xfat"])
  AM_CONDITIONAL([BUILD_FAT], [test "x${BITS}" = "xfat"])
  AM_CONDITIONAL([BUILD_FAT_OSX], [test "x${OS_TARGET}" = "xDarwin" && test "x${BITS}" = "xfat"])

  CONFIGURE_ARGS=""
  LIB_CFLAGS_32="-fPIC -m32"
  LIB_CFLAGS_64="-fPIC -m64"
  LIB_CXXFLAGS=""
  LIB_OBJCFLAGS=""
  OPENSSL_ARGS_32=""
  OPENSSL_ARGS_64=""
  AS_CASE([$host_os],
    [darwin*], [
      OPENSSL_ARGS_32="darwin-i386-cc ${LIB_CFLAGS_32}"
      OPENSSL_ARGS_64="darwin64-x86_64-cc ${LIB_CFLAGS_64}"
      AS_CASE([${BITS}],
        [32], [
          ADDITIONAL_FB_FLAGS="-DCMAKE_OSX_ARCHITECTURES=\"i386\""
        ],
        [64], [
          ADDITIONAL_FB_FLAGS="-DCMAKE_OSX_ARCHITECTURES=\"x86_64\""
        ],
        [fat], [
          ADDITIONAL_FB_FLAGS="-DCMAKE_OSX_ARCHITECTURES=\"i386;x86_64\""
        ]
      )
      CORE_LIBS="${CORE_LIBS} -framework Cocoa -framework Security"
      STRIP="${STRIP} -x -S"
    ],
    [linux*], [
      OPENSSL_ARGS_32="linux-elf ${LIB_CFLAGS_32}"
      OPENSSL_ARGS_64="linux-x86_64 ${LIB_CFLAGS_64}"
      AS_CASE([${BITS}],
        [32], [
        ],
        [64], [
        ]
      )
    ],
    [freebsd*], [
      OPENSSL_ARGS_32="BSD-x86-elf ${LIB_CFLAGS_32}"
      OPENSSL_ARGS_64="BSD-x86_64 ${LIB_CFLAGS_64}"
      AS_CASE([$BITS],
        [32], [
        ],
        [64], [
        ]
      )
    ],
    [mingw*], [
      CORE_CPPFLAGS='-I$(top_srcdir)/static-libs/libs-built/windows/x86 '"${CORE_CPPFLAGS}"
      AC_DEFINE(TGT_SYSTEM, TGT_WIN, [Target system is Windows.])
      AC_DEFINE(__USE_MINGW_ANSI_STDIO, 1, [MinGW requires this for GNU format specifiers?])
      AS_CASE([${BITS}],
        [32], [
          CONFIGURE_ARGS="--host=\"$host_alias\" --target=\"$target_alias\""
          OPENSSL_ARGS_32="--cross-compile-prefix=\"$host_alias-\" mingw enable-static-engine ${LIB_CFLAGS_32}"
          CROSSCOMPILE_PREPARATION_EXPORTS="export CC=\"${host_alias}-gcc\" && export LD=\"${host_alias}-ld\" && "
        ],
        [
          AC_MSG_ERROR([You can only build 32-bit applications using MinGW.])
        ]
      )
    ]
  )
#  LIB_CXXFLAGS=$LIB_CFLAGS
#  AC_SUBST(LIB_CFLAGS)
  AC_SUBST(LIB_CFLAGS_32)
  AC_SUBST(LIB_CFLAGS_64)
#  AC_SUBST(LIB_CXXFLAGS)
  AC_SUBST(LIB_OBJCFLAGS)
  AC_SUBST(OPENSSL_ARGS_32)
  AC_SUBST(OPENSSL_ARGS_64)
  AC_SUBST(CONFIGURE_ARGS)
  AC_SUBST(CROSSCOMPILE_PREPARATION_EXPORTS)

  # Compiler and linker need to know about the target architecture.
  CORE_CFLAGS="${CORE_CFLAGS} $LIB_CFLAGS"
  CORE_CXXFLAGS="${CORE_CXXFLAGS} $LIB_CFLAGS"
  CORE_OBJCFLAGS="${CORE_OBJCFLAGS} $LIB_CFLAGS"
  CORE_LDFLAGS="${CORE_LDFLAGS} $LIB_CFLAGS"

  CORE_CFLAGS_32="${CORE_CFLAGS} $LIB_CFLAGS_32"
  CORE_CFLAGS_64="${CORE_CFLAGS} $LIB_CFLAGS_64"
  CORE_OBJCFLAGS_32="${CORE_OBJCFLAGS} $LIB_CFLAGS_32"
  CORE_OBJCFLAGS_64="${CORE_OBJCFLAGS} $LIB_CFLAGS_64"
  CORE_LDFLAGS_32="${CORE_LDFLAGS} $LIB_CFLAGS_32"
  CORE_LDFLAGS_64="${CORE_LDFLAGS} $LIB_CFLAGS_64"
  AC_SUBST(CORE_CPPFLAGS_32)
  AC_SUBST(CORE_CPPFLAGS_64)
  AC_SUBST(CORE_CFLAGS_32)
  AC_SUBST(CORE_CFLAGS_64)
  AC_SUBST(CORE_OBJCFLAGS_32)
  AC_SUBST(CORE_OBJCFLAGS_64)
  AC_SUBST(CORE_LDFLAGS_32)
  AC_SUBST(CORE_LDFLAGS_64)

  AS_CASE([$host_os],
    [mingw*], [
      # Don't search.
    ],
    [
      # libdl
      # The dlopen() function is in the C library on *BSD systems and in libdl
      # on glibc based systems.
      CPPFLAGS="$PASSED_CPPFLAGS"
      CFLAGS="$PASSED_CFLAGS"; CXXFLAGS="$PASSED_CXXFLAGS";
      LDFLAGS="$PASSED_LDFLAGS"; LIBS=""
      AC_SEARCH_LIBS([dlopen], [dl dld], , [
        AC_MSG_ERROR([Could not find dlopen() in expected locations. Install or/and add the comprising library into the list of tested libraries.])
      ])
      CORE_LDFLAGS="${CORE_LDFLAGS} $LDFLAGS"
      CORE_LIBS="${CORE_LIBS} $LIBS"

      # libpthread
      CPPFLAGS="$PASSED_CPPFLAGS"
      CFLAGS="$PASSED_CFLAGS"; CXXFLAGS="$PASSED_CXXFLAGS";
      LDFLAGS="$PASSED_LDFLAGS"; LIBS=""
      AX_PTHREAD([
        AC_DEFINE(HAVE_PTHREAD, 1, [Define to 1 if libpthread available.])
        CFLAGS=" $PTHREAD_CFLAGS $CFLAGS"
        LDFLAGS=" $LDFLAGS $PTHREAD_CFLAGS"
        LIBS=" $PTHREAD_LIBS $LIBS"
        CC="$PTHREAD_CC"

        AC_CHECK_FUNCS([ \
          pthread_kill \
          pthread_spin_init \
        ])

        CORE_CFLAGS="${CORE_CFLAGS} $CFLAGS"
        CORE_LDFLAGS="${CORE_LDFLAGS} $LDFLAGS"
        CORE_LIBS="${CORE_LIBS} $LIBS"
      ], [
        AC_MSG_ERROR([Could not find pthread library.])
      ])
    ]
  )

  ], [
  AC_MSG_RESULT([no]) # Dynamic linking.

  # OpenSSL
  CPPFLAGS="$PASSED_CPPFLAGS"
  CFLAGS="$PASSED_CFLAGS"; CXXFLAGS="$PASSED_CXXFLAGS";
  LDFLAGS="$PASSED_LDFLAGS"; LIBS=""
  AC_ARG_WITH([openssl],
    [AS_HELP_STRING([--with-openssl=PATH], [Specifies OpenSSL installation directory.])],
    [
      OPENSSL_CPPFLAGS="-I$withval/include"
      OPENSSL_LDFLAGS="-L$withval/lib -Wl,-rpath,$withval/lib"
    ]
  )
  CPPFLAGS="${CPPFLAGS} ${OPENSSL_CPPFLAGS}"
  LDFLAGS="${LDFLAGS} ${OPENSSL_LDFLAGS}"
  AC_SEARCH_LIBS([SSL_get_peer_cert_chain], [ssl], [], [AC_MSG_ERROR([libssl not found])]) # Only DANE.
  AC_SEARCH_LIBS([OpenSSL_add_all_digests], [crypto], [], [AC_MSG_ERROR([libcrypto not found])])
  CORE_CPPFLAGS="${CORE_CPPFLAGS} $CPPFLAGS"
  CORE_LDFLAGS="${CORE_LDFLAGS} $LDFLAGS"
  CORE_LIBS="${CORE_LIBS} $LIBS"

  # libldns
  CPPFLAGS="$PASSED_CPPFLAGS"
  CFLAGS="$PASSED_CFLAGS"; CXXFLAGS="$PASSED_CXXFLAGS";
  LDFLAGS="$PASSED_LDFLAGS"; LIBS=""
  AC_ARG_WITH([ldns],
    [AS_HELP_STRING([--with-ldns=PATH], [Specifies libldns installation directory.])],
    [
      LDNS_CPPFLAGS="-I$withval/include"
      LDNS_LDFLAGS="-L$withval/lib -Wl,-rpath,$withval/lib"
    ]
  )
  CPPFLAGS="${CPPFLAGS} ${LDNS_CPPFLAGS}"
  LDFLAGS="${LDFLAGS} ${LDNS_LDFLAGS}"
  AC_SEARCH_LIBS([ldns_dname_new_frm_str], [ldns], [], [AC_MSG_ERROR([libldns not found])])
  CORE_CPPFLAGS="${CORE_CPPFLAGS} $CPPFLAGS"
  CORE_LDFLAGS="${CORE_LDFLAGS} $LDFLAGS"
  CORE_LIBS="${CORE_LIBS} $LIBS"

  # libunbound
  CPPFLAGS="$PASSED_CPPFLAGS"
  CFLAGS="$PASSED_CFLAGS"; CXXFLAGS="$PASSED_CXXFLAGS";
  LDFLAGS="$PASSED_LDFLAGS"; LIBS=""
  AC_ARG_WITH([unbound],
    [AS_HELP_STRING([--with-unbound=PATH], [Specifies libunbound installation directory.])],
    [
      UNBOUND_CPPFLAGS="-I$withval/include"
      UNBOUND_LDFLAGS="-L$withval/lib -Wl,-rpath,$withval/lib"
    ]
  )
  CPPFLAGS="${CPPFLAGS} ${UNBOUND_CPPFLAGS}"
  LDFLAGS="${LDFLAGS} ${UNBOUND_LDFLAGS}"
  AC_SEARCH_LIBS([ub_ctx_create], [unbound], [], [AC_MSG_ERROR([libunbound not found])])
  CORE_CPPFLAGS="${CORE_CPPFLAGS} $CPPFLAGS"
  CORE_LDFLAGS="${CORE_LDFLAGS} $LDFLAGS"
  CORE_LIBS="${CORE_LIBS} $LIBS"

  # Checks whether libldns knows LDNS_RR_TYPE_TLSA
  AC_MSG_CHECKING([whether libldns knows LDNS_RR_TYPE_TLSA])
  cat>conftest.c<<EOF
  #include <ldns/ldns.h>
  int main(void) {
    volatile enum ldns_enum_rr_type rr_type;
    rr_type = LDNS_RR_TYPE_TLSA;
    return 0;
  }
EOF
  AS_IF([$CC $CORE_CPPFLAGS $CORE_CFLAGS conftest.c -o conftest $CORE_LDFLAGS -lldns > /dev/null 2>&1], [
    AC_MSG_RESULT([yes])
    dnl C preprocessor
    AC_DEFINE(HAVE_LDNS_RR_TYPE_TLSA, 1, [Libpcap knows pcap_create and pcap_activate.])
  ], [
    AC_MSG_RESULT([no])
    AC_MSG_ERROR(["Libldns does not know LDNS_RR_TYPE_TLSA."])
  ])
  #rm -f conftest.c conftest

  ]
)
dnl conditional compilation
AM_CONDITIONAL([STATIC_CORE], [test "x$enable_static_linking" = "xyes"])


# Check whether to build NPAPI core -- default off.
AC_MSG_CHECKING([Whether to build NPAPI-based extensions.])
AC_ARG_ENABLE([npapi-extensions],
  AS_HELP_STRING([--enable-npapi-extensions], [Build NPAPI extensions.]))
AS_IF([test "x$enable_npapi_extensions" = "xyes"], [
    AC_MSG_RESULT([yes]) # Enable NPAPI.
  ], [
    AC_MSG_RESULT([no]) # Disable NPAPI.
  ]
)
dnl conditional compilation
AM_CONDITIONAL([NPAPI_CORE], [test "x$enable_npapi_extensions" = "xyes"])

# MinGW requires some additional quirks to build libubound.
AS_CASE([$host_os],
  [mingw*], [AM_CONDITIONAL([MINGW_BUILD], [true])],
  [AM_CONDITIONAL([MINGW_BUILD], [false])]
)


###############################################################################
# Optional core dependencies.
###############################################################################

# Pick correct CA store, auto is default.
CA_STORE=-1
AC_ARG_WITH([ca-store],
  [AS_HELP_STRING([--with-ca-store=[auto|directory|none|nss|nss_cert8|osx|win]], [Which CA store to use, 'auto' is default.])],
  [
    # Values are defined in dane-plug.c .
    AS_CASE([$withval],
      [auto], [CA_STORE=-1],
      [none], [CA_STORE=0],
      [directory], [CA_STORE=1],
      [nss], [CA_STORE=2],
      [nss_cert8], [CA_STORE=3],
      [osx], [CA_STORE=4],
      [win], [CA_STORE=5],
      [AC_MSG_WARN(["Unknown CA store option '$withval'."])]
    )
  ])
# Set default value according to the target system.
# FIXME: Missing MinGW.
AS_IF([test $CA_STORE = -1], [
  AS_CASE([$host_os],
    [darwin*], [CA_STORE=4],
    [mingw*], [CA_STORE=5],
    [CA_STORE=1]
  )
])
AS_IF([test $CA_STORE = -1], [
  AC_MSG_ERROR(["CA store could not be determined."])
])
AC_DEFINE_UNQUOTED([CA_STORE], [${CA_STORE}], [Select which CA store to use])
AM_CONDITIONAL([CA_STORE_DIR], [test $CA_STORE = 1])
AM_CONDITIONAL([CA_STORE_NSS], [test $CA_STORE = 2])
AM_CONDITIONAL([CA_STORE_OSX], [test $CA_STORE = 4])
AM_CONDITIONAL([CA_STORE_WIN], [test $CA_STORE = 5])

# Select a log target.
LOG_TGT=-1
AC_ARG_WITH([log-tgt],
  [AS_HELP_STRING([--with-log-tgt=[auto,dflt,osx]], [Which log target to use, 'auto' is default.])],
  [
    AS_CASE([$withval],
      [auto], [LOG_TGT=-1],
      [dflt], [LOG_TGT=0],
      [osx], [LOG_TGT=1],
      [AC_MSG_WARN(["Unknown log target option '$withval'."])]
    )
  ])
# Set default value according to the target system.
AS_IF([test $LOG_TGT = -1], [
  AS_CASE([$host_os],
    [darwin*], [LOG_TGT=1],
    [LOG_TGT=0]
  )
])
AS_IF([test $LOG_TGT = -1], [
  AC_MSG_ERROR(["Log target could not be determined."])
])
AM_CONDITIONAL([LOG_DFLT], [test $LOG_TGT = 0])
AM_CONDITIONAL([LOG_OSX], [test $LOG_TGT = 1])


###############################################################################
# Extension packages.
###############################################################################

AM_CONDITIONAL([EXTPKG_MOZZ_JC], [true]) # Mozilla Firefox js-ctypes.
#AM_CONDITIONAL([EXTPKG_CR_NM], [true]) # Chromium/Chrome native messaging.
AM_CONDITIONAL([EXTPKG_CR_NM], [test "x${OS_TARGET}" = "xDarwin" || test "x${BITS}" != "xfat"]) # Chromium/Chrome native messaging.
AM_CONDITIONAL([EXTPKG_MOZZ_NP], [test "x$enable_npapi_extensions" = "xyes"]) # Mozilla Firefox NPAPI.
AM_CONDITIONAL([EXTPKG_SAF_NP], [test "x$OS_TARGET" = "xDarwin" && test "x$enable_npapi_extensions" = "xyes"]) # Apple Safari NPAPI.


CPPFLAGS="${CORE_CPPFLAGS}"
CFLAGS="${CORE_CFLAGS}"; CXXFLAGS="${CORE_CXXFLAGS}";
#LDFLAGS="${CORE_LDFLAGS}"; LIBS="${CORE_LIBS}"


# Checks for header files.
AC_CHECK_HEADERS([ \
  arpa/inet.h \
  limits.h \
  netdb.h \
  netinet/in.h \
  stdint.h \
  stdlib.h \
  string.h \
  sys/socket.h \
  unistd.h \
])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_INT8_T
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AS_CASE([$host_os],
  [mingw*], [
    # Don't check for malloc on MingGW.
  ],
  [AC_FUNC_MALLOC]
)
AC_CHECK_FUNCS([ \
  gethostbyname \
  inet_ntoa \
  memset \
  socket \
  strchr \
  strerror \
  strspn \
  strstr \
])

# No parameters shall be passed via default variables.
#CPPFLAGS=""
#CFLAGS=""; CXXFLAGS="";
LDFLAGS=""; LIBS=""

# Default preprocessor flags.
#AC_SUBST([AM_CPPFLAGS], [""])


AC_CONFIG_FILES([ \
  Makefile \
  static-libs/Makefile \
  core_js-ctypes/Makefile \
  core_js-ctypes/bits-32/Makefile \
  core_js-ctypes/bits-64/Makefile \
  core_js-ctypes/bits-fat/Makefile \
  core_native-msg/Makefile \
  core_native-msg/bits-32/Makefile \
  core_native-msg/bits-64/Makefile \
  core_native-msg/bits-fat/Makefile \
  core_npapi/Makefile \
  add-on/Makefile \
  Version
])

AC_OUTPUT
