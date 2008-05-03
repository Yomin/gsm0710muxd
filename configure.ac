AC_PREREQ(2.53)
AC_INIT()

AM_INIT_AUTOMAKE(gsm0710muxd, 0.9.1)
AM_CONFIG_HEADER(config.h)

AM_MAINTAINER_MODE

AC_PREFIX_DEFAULT(/usr/local)

if (test "${CFLAGS}" = ""); then
	CFLAGS="-Wall -O2"
fi

AC_LANG_C

AC_PROG_CC
AC_PROG_INSTALL

AC_PATH_PROG(VALAC, [valac])

PKG_CHECK_MODULES(GLIB, glib-2.0 >= 2.10, dummy=yes,
				AC_MSG_ERROR(libglib-2.0 is required))
AC_SUBST(DBUS_CFLAGS)
AC_SUBST(DBUS_LIBS)

PKG_CHECK_MODULES(DBUS, dbus-1 >= 1.0, dummy=yes,
				AC_MSG_ERROR(libdbus is required))
AC_SUBST(DBUS_CFLAGS)
AC_SUBST(DBUS_LIBS)

PKG_CHECK_MODULES(DBUS_GLIB, dbus-glib-1 >= 0.70, dummy=yes,
				AC_MSG_ERROR(libdbus-glib is required))
AC_SUBST(DBUS_GLIB_CFLAGS)
AC_SUBST(DBUS_GLIB_LIBS)

DBUS_BINDING_TOOL="dbus-binding-tool"
AC_SUBST(DBUS_BINDING_TOOL)

AC_OUTPUT(Makefile src/Makefile data/Makefile)
