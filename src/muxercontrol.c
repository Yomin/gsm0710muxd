/*
	Vala MuxerControl Code

	valac --vapidir=src --pkg=gsm0710muxd --pkg=dbus-glib-1 --ccode src/muxercontrol.vala
*/

#include "muxercontrol.h"
#include <dbus/dbus-glib-lowlevel.h>
#include <dbus/dbus-glib.h>



enum {
	MUXER_ALLOC_ERROR
} MuxerError;

#define MUXER_ERROR ( muxer_error_quark() )
#define MUXER_ERROR_TYPE ( muxer_error_get_type() )

#define ENUM_ENTRY(NAME, DESC) { NAME, "" #NAME "", DESC }

static GQuark muxer_error_quark(void)
{
	static GQuark quark = 0;
	if (!quark)
		quark = g_quark_from_static_string("muxer");

	return quark;
}

static GType muxer_error_get_type(void)
{
	static GType etype = 0;
	if (etype == 0) {
		static const GEnumValue values[] = {
			ENUM_ENTRY(MUXER_ALLOC_ERROR, "NoChannel"),
			{ 0, 0, 0 }
		};

		etype = g_enum_register_static("muxer", values);
	}

return etype;
}


enum  {
	MUXER_CONTROL_DUMMY_PROPERTY
};
static gpointer muxer_control_parent_class = NULL;



void muxer_control_run (MuxerControl* self) {
	GError * inner_error;
	DBusGConnection* conn;
	g_return_if_fail (IS_MUXER_CONTROL (self));
	inner_error = NULL;
	conn = dbus_g_bus_get (DBUS_BUS_SYSTEM, &inner_error);
	if (inner_error != NULL) {
		g_critical ("file %s: line %d: uncaught error: %s", __FILE__, __LINE__, inner_error->message);
		g_clear_error (&inner_error);
	}
	(conn == NULL ? NULL : (conn = (dbus_g_connection_unref (conn), NULL)));
}


gboolean muxer_control_reset_modem (MuxerControl* self, const char* origin) {
	g_return_val_if_fail (IS_MUXER_CONTROL (self), FALSE);
	g_return_val_if_fail (origin != NULL, FALSE);
	return c_reset_modem (origin);
}


gboolean muxer_control_set_power (MuxerControl* self, const char* origin, gboolean on) {
	g_return_val_if_fail (IS_MUXER_CONTROL (self), FALSE);
	g_return_val_if_fail (origin != NULL, FALSE);
	return c_set_power (origin, on);
}


gboolean muxer_control_get_power (MuxerControl* self, const char* origin, gboolean on) {
	g_return_val_if_fail (IS_MUXER_CONTROL (self), FALSE);
	g_return_val_if_fail (origin != NULL, FALSE);
	return c_get_power (origin);
}


gboolean muxer_control_alloc_channel (MuxerControl* self, const char* origin, const char** channel, GError** error) {
	g_return_val_if_fail (IS_MUXER_CONTROL (self), FALSE);
	g_return_val_if_fail (origin != NULL, FALSE);
	g_return_val_if_fail (channel != NULL, FALSE);
	gboolean success = c_alloc_channel (origin, channel);
	if (!success)
		g_set_error( error, MUXER_ERROR, MUXER_ALLOC_ERROR, "All channels are used" );
	return success;
}

MuxerControl* muxer_control_gen (void) {
	dbus_g_error_domain_register(MUXER_ERROR, "org.freesmartphone.GSM.MUX", MUXER_ERROR_TYPE);
	return muxer_control_new ();
}


/*[DBusInterface(name = "org.mobile.mux.RemoteInterface")]
interface Mux.RemoteInterface;*/
MuxerControl* muxer_control_new (void) {
	MuxerControl * self;
	self = g_object_newv (TYPE_MUXER_CONTROL, 0, NULL);
	return self;
}


static void muxer_control_class_init (MuxerControlClass * klass) {
	muxer_control_parent_class = g_type_class_peek_parent (klass);
}


static void muxer_control_init (MuxerControl * self) {
}


GType muxer_control_get_type (void) {
	static GType muxer_control_type_id = 0;
	if (G_UNLIKELY (muxer_control_type_id == 0)) {
		static const GTypeInfo g_define_type_info = { sizeof (MuxerControlClass), (GBaseInitFunc) NULL, (GBaseFinalizeFunc) NULL, (GClassInitFunc) muxer_control_class_init, (GClassFinalizeFunc) NULL, NULL, sizeof (MuxerControl), 0, (GInstanceInitFunc) muxer_control_init };
		muxer_control_type_id = g_type_register_static (G_TYPE_OBJECT, "MuxerControl", &g_define_type_info, 0);
	}
	return muxer_control_type_id;
}




