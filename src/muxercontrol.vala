/*
	Vala MuxerControl Code

	valac --vapidir=src --pkg=gsm0710muxd --pkg=dbus-glib-1 --ccode src/muxercontrol.vala
*/

//[DBusInterface(name = "org.mobile.mux.RemoteInterface")]
//interface Mux.RemoteInterface;

public class MuxerControl : GLib.Object
{
	public void run()
	{
		DBus.Connection conn = DBus.Bus.get(DBus.BusType.SYSTEM);
	}
	public bool reset_modem(string origin)
	{
		return gsm0710muxd.c_reset_modem(origin);
	}
	public bool set_power(string origin, bool on)
	{
		return gsm0710muxd.c_set_power(origin, on);
	}
	public bool get_power(string origin)
	{
		return gsm0710muxd.c_get_power(origin);
	}
	public bool alloc_channel(string origin, string channel)
	{
		return gsm0710muxd.c_alloc_channel(origin, channel);
	}
	public static MuxerControl gen()
	{
		return new MuxerControl();
	}
}
