package dev.ard.agent;

import android.app.Activity;
import android.content.Context;
import android.util.Log;
import android.widget.Toast;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

/**
 * In-app certificate enrolment.
 *
 * Getting a certificate onto a device by hand needs a laptop: mint a certificate on the
 * gateway, adb push two files, and move them into the app's private directory with
 * run-as. That puts a device private key in a terminal, in a push, and in shell history,
 * and it requires physical access every time a device is added.
 *
 * Here the device generates its own key and asks for a certificate. What the operator
 * does is type one code shown on this screen into a command on the gateway host. No key
 * material moves, and the phone is never touched by anything but its own button.
 *
 * The cryptography lives in the agent binary rather than here, because that is where the
 * PKI code already is and Java would need a second implementation of it. This class runs
 * the binary and parses its output.
 *
 * The enrolment port is derived from the gateway address rather than configured
 * separately. It is a different port from the one the agent connects to, and having one
 * field for "where is the gateway" is one fewer thing to get wrong; the derivation is
 * visible in the UI text so it is not a hidden rule.
 */
final class Enrol {

    /** Matches ARD_LISTEN_ENROL in deploy/ard-server.env. */
    private static final int ENROL_PORT = 7200;

    private Enrol() {}

    /** What the operator needs in order to approve, and what the user must read out. */
    static final class Result {
        final boolean ok;
        final String code;         // claim code to type on the gateway host
        final String fingerprint;  // gateway certificate the device actually saw
        final String detail;

        Result(boolean ok, String code, String fingerprint, String detail) {
            this.ok = ok;
            this.code = code;
            this.fingerprint = fingerprint;
            this.detail = detail;
        }
    }

    /**
     * Runs enrolment and blocks until it finishes.
     *
     * Blocking is deliberate and it is why this cannot simply run on the main thread:
     * the flow waits for a human to read a code and type it somewhere else, which can
     * take a minute. The caller is expected to be a background thread, and the UI is
     * updated from the main thread by whoever called this.
     */
    static Result run(Context ctx, String gateway, String deviceId, String deviceName) {
        String host = hostOf(gateway);
        if (host.isEmpty()) {
            return fail("the gateway address is not set");
        }
        if (deviceId == null || deviceId.isEmpty()) {
            return fail("the device id is not set");
        }
        File binary;
        try {
            // install() throws rather than returning null when the binary is missing or
            // not executable, which is the case that matters: an APK built without
            // extractNativeLibs cannot run its own agent at all.
            binary = AgentBinary.install(ctx);
        } catch (RuntimeException e) {
            Log.e("ard-enrol", "agent binary unavailable", e);
            return fail(e.getMessage() == null ? e.toString() : e.getMessage());
        }
        File outDir = Config.dir(ctx);

        List<String> argv = new ArrayList<>();
        argv.add(binary.getAbsolutePath());
        argv.add("-enrol");
        argv.add(host + ":" + ENROL_PORT);
        argv.add("-enrol-id");
        argv.add(deviceId);
        if (deviceName != null && !deviceName.isEmpty()) {
            argv.add("-enrol-name");
            argv.add(deviceName);
        }
        argv.add("-enrol-out");
        argv.add(outDir.getAbsolutePath());

        ProcessBuilder pb = new ProcessBuilder(argv);
        pb.redirectErrorStream(true);
        try {
            Process p = pb.start();
            StringBuilder all = new StringBuilder();
            try (BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
                String line;
                while ((line = r.readLine()) != null) {
                    all.append(line).append('\n');
                    // Surface the code the moment it appears, so the operator can start
                    // typing while the device is still waiting.
                    if (line.startsWith("code=") && line.length() > 5) {
                        String code = line.substring(5).trim();
                        Toast.makeText(ctx, "Enrolment code: " + code, Toast.LENGTH_LONG).show();
                    }
                }
            }
            int rc = p.waitFor();
            String output = all.toString();
            Log.i("ard-enrol", "exit " + rc + "\n" + output);

            String code = field(output, "code=");
            String fingerprint = field(output, "gateway_fingerprint=");
            if (rc == 0 && output.contains("enrolled=")) {
                return new Result(true, code, fingerprint, "enrolled");
            }
            return new Result(false, code, fingerprint,
                    rc == 0 ? output.trim() : "enrolment failed (exit " + rc + "): " + output.trim());
        } catch (Exception e) {
            Log.e("ard-enrol", "enrolment failed", e);
            return fail(e.toString());
        }
    }

    /**
     * True when this device already holds a certificate.
     *
     * Checked so the UI can say what is missing instead of letting an agent start with
     * no identity and fail later with a TLS error.
     */
    static boolean enrolled(Context ctx) {
        File dir = Config.dir(ctx);
        return new File(dir, "device.crt").length() > 0
                && new File(dir, "device.key").length() > 0
                && new File(dir, "ca.crt").length() > 0;
    }

    /** Deletes the stored identity, so a device can be re-enrolled from scratch. */
    static void clear(Context ctx) {
        File dir = Config.dir(ctx);
        for (String name : new String[]{"device.crt", "device.key", "ca.crt", "ca.key"}) {
            File f = new File(dir, name);
            if (f.exists() && !f.delete()) {
                Log.w("ard-enrol", "could not delete " + f);
            }
        }
    }

    /** host:port or host, reduced to the host. Empty when there is nothing usable. */
    static String hostOf(String gateway) {
        if (gateway == null) {
            return "";
        }
        String g = gateway.trim();
        int at = g.lastIndexOf('@');
        if (at >= 0) {
            g = g.substring(at + 1);
        }
        if (g.startsWith("[")) {                       // [v6]:port
            int end = g.indexOf(']');
            return end > 0 ? g.substring(1, end) : "";
        }
        int colon = g.lastIndexOf(':');
        return colon > 0 ? g.substring(0, colon) : g;
    }

    private static String field(String output, String prefix) {
        for (String line : output.split("\n")) {
            if (line.startsWith(prefix)) {
                return line.substring(prefix.length()).trim();
            }
        }
        return "";
    }

    private static Result fail(String detail) {
        return new Result(false, "", "", detail);
    }

    /** Convenience for callers on the main thread. */
    static void runAsync(final Activity act, final String gateway,
                         final String deviceId, final String deviceName) {
        final Context app = act.getApplicationContext();
        new Thread(() -> {
            final Result r = run(app, gateway, deviceId, deviceName);
            act.runOnUiThread(() -> {
                if (!r.ok) {
                    Toast.makeText(act, r.detail, Toast.LENGTH_LONG).show();
                }
            });
        }, "ard-enrol").start();
    }
}