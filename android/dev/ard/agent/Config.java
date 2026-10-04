package dev.ard.agent;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;

/**
 * Agent settings, stored as plain preferences.
 *
 * Values are read once at spawn and never changed while running: the agent is a
 * command-line process, and rewriting its flags underneath it would require either
 * a restart or a control channel that does not exist yet. Restarting is honest and
 * debuggable.
 */
public class Config {

    private static final String PREFS = "ard_config";

    // Defaults assume a gateway reachable by name. Everything is overridable in
    // the UI because no two deployments are alike: the gateway host may be a DNS
    // name, a public IP, or a tunnel.
    private static final String DEF_GATEWAY = "<gateway-address>:7000";
    private static final String DEF_SERVER_NAME = "<hostname>";
    private static final String DEF_DEVICE_ID = Build.MODEL.replaceAll("[^A-Za-z0-9._-]", "-");
    private static final String DEF_DEVICE_NAME = Build.MANUFACTURER + " " + Build.MODEL;
    private static final String DEF_ADBD = "";

    public final String gateway;
    public final String serverName;
    public final String deviceId;
    public final String deviceName;
    public final String adbd;

    public Config(String gateway, String serverName, String deviceId,
                  String deviceName, String adbd) {
        this.gateway = gateway;
        this.serverName = serverName;
        this.deviceId = deviceId;
        this.deviceName = deviceName;
        this.adbd = adbd;
    }

    public static Config load(Context ctx) {
        SharedPreferences p = prefs(ctx);
        return new Config(
                p.getString("gateway", DEF_GATEWAY),
                p.getString("server_name", DEF_SERVER_NAME),
                p.getString("device_id", DEF_DEVICE_ID),
                p.getString("device_name", DEF_DEVICE_NAME),
                p.getString("adbd", DEF_ADBD));
    }

    public void save(Context ctx) {
        prefs(ctx).edit()
                .putString("gateway", gateway)
                .putString("server_name", serverName)
                .putString("device_id", deviceId)
                .putString("device_name", deviceName)
                .putString("adbd", adbd)
                .apply();
    }

    private static SharedPreferences prefs(Context ctx) {
        return ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    public String[] argv(Context ctx, String bin) {
        java.util.List<String> a = new java.util.ArrayList<>();
        a.add(bin);
        a.add("-gateway");    a.add(gateway);
        if (!serverName.isEmpty()) { a.add("-server-name"); a.add(serverName); }
        a.add("-device");     a.add(deviceId);
        if (!deviceName.isEmpty()) { a.add("-name"); a.add(deviceName); }
        a.add("-adbd");       a.add(adbd);
        // -ca takes the directory holding ca.crt; the agent resolves the file
        // itself so the flag cannot be pointed at the wrong name.
        java.io.File certDir = Config.certDir(ctx);
        a.add("-ca");         a.add(new java.io.File(certDir, "ca.crt").getAbsolutePath());
        // The working directory is also the certificate directory, so a relative
        // and an absolute path name the same place. Two sources of truth for one
        // path is how "no such file or directory" appears in a path that exists.
        a.add("-cert");       a.add(new java.io.File(Config.dir(ctx), "device.crt").getAbsolutePath());
        a.add("-key");        a.add(new java.io.File(Config.dir(ctx), "device.key").getAbsolutePath());
        return a.toArray(new String[0]);
    }

    /** One directory holds the agent, the CA and the device identity. */
    public static java.io.File certDir(Context ctx) {
        return dir(ctx);
    }

    public String summary() {
        return deviceId + " -> " + gateway + " (adbd " + adbd + ")";
    }

    /** Where certificates and the agent binary live. */
    public static java.io.File dir(Context ctx) {
        java.io.File d = new java.io.File(ctx.getFilesDir(), "ard");
        //noinspection ResultOfMethodCallIgnored
        d.mkdirs();
        return d;
    }
}