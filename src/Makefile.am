sbin_PROGRAMS = gsm0710muxd

gsm0710muxd_SOURCES = gsm0710muxd.c

gsm0710muxd_LDADD = @DBUS_GLIB_LIBS@ @DBUS_LIBS@ @GLIB_LIBS@

AM_CFLAGS = @GLIB_CFLAGS@ @DBUS_CFLAGS@ @DBUS_GLIB_CFLAGS@

BUILT_SOURCES = mux-glue.h

nodist_gsm0710muxd_SOURCES = $(BUILT_SOURCES)

CLEANFILES = mux-glue.h

EXTRA_DIST = mux.xml muxercontrol.vala gsm0710muxd.vapi \
				muxercontrol.h muxercontrol.c

MAINTAINERCLEANFILES = Makefile.in

mux-glue.h: mux.xml
	$(DBUS_BINDING_TOOL) --prefix=mux --mode=glib-server --output=$@ $<

vala: muxercontrol.vala
	$(VALAC) --vapidir=$(top_srcdir)/src --pkg=gsm0710muxd --pkg=dbus-glib-1 --ccode $<
