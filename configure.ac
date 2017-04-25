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

AC_INIT([k8s-ts-ingress], [D.1.0])

AC_CONFIG_HEADERS([autoconf.h])

AC_ARG_WITH([tsxs],
	[AS_HELP_STRING([--with-tsxs[=PATH]], [path to Traffic Server tsxs])],
	[TSXS="$withval"])
AC_CHECK_PROG(TSXS, tsxs)

PIC_FLAG=-fPIC
AC_ARG_WITH([cc-pic-flag],
	[AS_HELP_STRING([--with-cc-pic-flag[=FLAG]],
			[cc flag to produce position independent code [-fPIC]])],
	[PIC_FLAG="$withval"])
CFLAGS="$CFLAGS $PIC_FLAG"

AS_IF([test -z "${TSXS}"], [
	AC_ERROR([could not find tsxs; maybe you need --with-tsxs=/path/to/tsxs])
])

TS_CC=`$TSXS -q CC`
TS_CFLAGS=`$TSXS -q CFLAGS`
TS_INCDIR=`$TSXS -q INCLUDEDIR`
TS_PLUGINDIR=`$TSXS -q LIBEXECDIR`
AC_SUBST(TS_CFLAGS)
AC_SUBST(TS_INCDIR)
AC_SUBST(TS_PLUGINDIR)

AC_LANG_C
AC_PROG_CC([$TS_CC])

PKG_CHECK_MODULES(JSON, json-c)
AC_SUBST([JSON_CFLAGS])
AC_SUBST([JSON_LIBS])

AC_CHECK_LIB(ssl, SSL_library_init, [], [AC_ERROR([could not find OpenSSL])])

AC_OUTPUT(Makefile)
