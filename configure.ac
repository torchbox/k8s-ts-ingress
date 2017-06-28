dnl vim:set sw=8 ts=8 noet:
dnl
dnl Copyright (c) 2016-2017 Torchbox Ltd.
dnl
dnl Permission is granted to anyone to use this software for any purpose,
dnl including commercial applications, and to alter it and redistribute it
dnl freely.
dnl
dnl THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
dnl IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
dnl FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
dnl AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
dnl LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
dnl OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
dnl SOFTWARE.

AC_INIT([k8s-ts-ingress], [1.0.0-alpha8])

AC_CANONICAL_BUILD
AC_CANONICAL_HOST

AC_CONFIG_MACRO_DIRS([acinclude])
AC_CONFIG_HEADERS([autoconf.h])

AC_ARG_WITH([tsxs],
	[AS_HELP_STRING([--with-tsxs[=PATH]], [path to Traffic Server tsxs])],
	[TSXS="$withval"])

AS_IF([test -n "$TSXS" -a -x "$TSXS"], [
	AC_SUBST(TSXS)
], [
	TSXS=tsxs
	AC_CHECK_PROG(HAVE_TSXS, $TSXS, yes, no)

	AS_IF([test "${HAVE_TSXS}" != "yes"], [
		AC_ERROR([could not find tsxs; maybe you need --with-tsxs=/path/to/tsxs])
	])
])

PIC_FLAG=-fPIC
AC_ARG_WITH([cc-pic-flag],
	[AS_HELP_STRING([--with-cc-pic-flag[=FLAG]],
			[cc flag to produce position independent code [-fPIC]])],
	[PIC_FLAG="$withval"])
CFLAGS="$CFLAGS $PIC_FLAG"

TS_CC=`$TSXS -q CC`
TS_CXX=`$TSXS -q CXX`
TS_CFLAGS=`$TSXS -q CFLAGS`
TS_CXXFLAGS=`$TSXS -q CXXFLAGS`
TS_INCDIR=`$TSXS -q INCLUDEDIR`
TS_PLUGINDIR=`$TSXS -q LIBEXECDIR`
AC_SUBST(TS_CFLAGS)
AC_SUBST(TS_CXXFLAGS)
AC_SUBST(TS_INCDIR)
AC_SUBST(TS_PLUGINDIR)

AC_LANG_C
AC_PROG_CC([$TS_CC])
AC_PROG_CC_C99
AS_IF([test "$ac_cv_prog_cc_c99" = "no" ], [
	AC_ERROR([a C99 compiler is required to build this plugin])
])

AC_PROG_CXX([$TS_CXX])

PKG_CHECK_MODULES(JSON, json-c)
AC_SUBST([JSON_CFLAGS])
AC_SUBST([JSON_LIBS])

ACX_PTHREAD

PKG_CHECK_MODULES(ZLIB, zlib, [], [
	AC_CHECK_LIB(z, deflateInit2, [], [AC_ERROR([could not find zlib])])
])

AC_CHECK_LIB(ssl, SSL_CTX_new, [], [AC_ERROR([could not find OpenSSL])])
AC_CHECK_LIB(crypto, MD5_Update, [], [AC_ERROR([could not find OpenSSL])])

LIBCURL_CHECK_CONFIG([], [], [], [
	AC_MSG_ERROR([libcurl is required to build])
])

AC_OUTPUT([Makefile contrib/brotli/Makefile])
