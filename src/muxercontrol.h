/*
	Vala MuxerControl Code

	valac --vapidir=src --pkg=gsm0710muxd --pkg=dbus-glib-1 --ccode src/muxercontrol.vala
*/

#ifndef __MUXERCONTROL_H__
#define __MUXERCONTROL_H__

#include <glib.h>
#include <glib-object.h>
#include <stdlib.h>
#include <string.h>

G_BEGIN_DECLS


#define TYPE_MUXER_CONTROL (muxer_control_get_type ())
#define MUXER_CONTROL(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), TYPE_MUXER_CONTROL, MuxerControl))
#define MUXER_CONTROL_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST ((klass), TYPE_MUXER_CONTROL, MuxerControlClass))
#define IS_MUXER_CONTROL(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj), TYPE_MUXER_CONTROL))
#define IS_MUXER_CONTROL_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), TYPE_MUXER_CONTROL))
#define MUXER_CONTROL_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS ((obj), TYPE_MUXER_CONTROL, MuxerControlClass))

typedef struct _MuxerControl MuxerControl;
typedef struct _MuxerControlClass MuxerControlClass;
typedef struct _MuxerControlPrivate MuxerControlPrivate;

/*[DBusInterface(name = "org.mobile.mux.RemoteInterface")]
interface Mux.RemoteInterface;*/
struct _MuxerControl {
	GObject parent_instance;
	MuxerControlPrivate * priv;
};
struct _MuxerControlClass {
	GObjectClass parent_class;
};

void muxer_control_run (MuxerControl* self);
gboolean muxer_control_reset_modem (MuxerControl* self, const char* origin);
gboolean muxer_control_set_power (MuxerControl* self, const char* origin, gboolean on);
gboolean muxer_control_get_power (MuxerControl* self, const char* origin, gboolean on);
gboolean muxer_control_alloc_channel (MuxerControl* self, const char* origin, const char* channel, GError** error);
MuxerControl* muxer_control_gen (void);
MuxerControl* muxer_control_new (void);
GType muxer_control_get_type (void);


G_END_DECLS

#endif
