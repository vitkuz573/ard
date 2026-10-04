package dev.ard.agent;

import android.Manifest;
import android.app.Activity;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.text.method.ScrollingMovementMethod;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

/**
 * The whole user interface, and the whole deployment procedure.
 *
 * The goal of this screen is that installing the APK is the entire installation.
 * Everything a device needs that can be discovered locally is discovered here; the
 * only genuinely external value is the gateway address, and the UI says so rather
 * than making the user guess.
 */
public class MainActivity extends Activity {

    private EditText gateway, serverName, deviceId, deviceName, adbd;
    private CheckBox autostart;
    private TextView status;
    private Button toggle, scanBtn, clearBtn, enrolBtn;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(build());

        Config c = Config.load(this);
        gateway.setText(c.gateway);
        serverName.setText(c.serverName);
        deviceId.setText(c.deviceId);
        deviceName.setText(c.deviceName);
        adbd.setText(c.adbd);

        toggle.setOnClickListener(v -> onToggle());
        scanBtn.setOnClickListener(v -> discoverAdbd());
        clearBtn.setOnClickListener(v -> StatusStore.clear(this));
        autostart.setOnCheckedChangeListener((b, on) ->
                getSharedPreferences("ard_config", MODE_PRIVATE)
                        .edit().putBoolean("autostart", on).apply());
        autostart.setChecked(getSharedPreferences("ard_config", MODE_PRIVATE)
                .getBoolean("autostart", false));

        StatusStore.setListener(t -> status.setText(t));
        requestNotificationPermission();
    }

    private LinearLayout build() {
        int pad = dp(16);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(pad, pad, pad, pad);

        TextView intro = new TextView(this);
        intro.setText("This device becomes reachable by the ARD gateway. "
                + "The gateway address is the only thing you need to enter; "
                + "everything else is filled in from this device.");
        root.addView(intro);

        gateway = field(root, "Gateway address", "host:7000");
        serverName = field(root, "TLS server name", "must match the gateway certificate");
        deviceId = field(root, "Device ID", "unique, stable across reboots");
        deviceName = field(root, "Device name", "shown to operators");
        adbd = field(root, "adbd address", "discovered on this device");

        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        scanBtn = button("Discover adbd"); row.addView(scanBtn, weight(row));
        clearBtn = button("Clear log"); row.addView(clearBtn, weight(row));
        root.addView(row);

        autostart = new CheckBox(this);
        autostart.setText("Start automatically after reboot");
        root.addView(autostart);

        toggle = button("Start");
        root.addView(toggle);

        // Enrolment is a separate action from starting, because it is a separate
        // operation: it needs the operator, and until they have run one command on the
        // gateway there is nothing for the agent to connect with.
        enrolBtn = button(enrolLabel());
        enrolBtn.setOnClickListener(v -> onEnrol());
        root.addView(enrolBtn);

        TextView enrolHelp = new TextView(this);
        enrolHelp.setTextSize(11);
        enrolHelp.setText("First run only: press Enrol, then type the code it shows into "
                + "`ard-ca enrol -code <CODE>` on the gateway. The device creates its own "
                + "key, so nothing has to be copied to or from it.");
        root.addView(enrolHelp);

        status = new TextView(this);
        status.setTextIsSelectable(true);
        status.setTextSize(11);
        status.setMovementMethod(new ScrollingMovementMethod());
        ScrollView sc = new ScrollView(this);
        sc.addView(status);
        LinearLayout.LayoutParams lp =
                new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f);
        root.addView(sc, lp);

        return root;
    }

    private LinearLayout.LayoutParams weight(LinearLayout parent) {
        return new LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
    }

    private EditText field(LinearLayout root, String label, String hint) {
        TextView l = new TextView(this);
        l.setText(label);
        l.setPadding(0, dp(8), 0, 0);
        root.addView(l);
        EditText e = new EditText(this);
        e.setHint(hint);
        e.setSingleLine(true);
        root.addView(e);
        return e;
    }

    /** The button doubles as the status line: it says whether a certificate is held. */
    private String enrolLabel() {
        return Enrol.enrolled(this) ? "Re-enrol (replace certificate)" : "Enrol";
    }

    /**
     * Starts enrolment on a background thread.
     *
     * The flow blocks on a human reading a code off this screen and typing it into a
     * terminal elsewhere, so running it on the main thread would freeze the UI for as
     * long as the operator takes.
     */
    private void onEnrol() {
        Config c = Config.load(this);
        String gw = gateway.getText().toString().trim();
        String id = deviceId.getText().toString().trim();
        String name = deviceName.getText().toString().trim();
        if (gw.isEmpty() || id.isEmpty()) {
            toast("the gateway address and device id are required");
            return;
        }
        enrolBtn.setEnabled(false);
        enrolBtn.setText("Enrolling\u2026 read the code, then approve it on the gateway");
        Enrol.runAsync(this, gw, id, name);
        // The thread posts its own result to the UI thread. This only restores the
        // button, so the state shown is whatever is true once the work has settled.
        enrolBtn.postDelayed(() -> {
            enrolBtn.setEnabled(true);
            enrolBtn.setText(enrolLabel());
        }, 1000);
    }

    private Button button(String text) {
        Button b = new Button(this);
        b.setText(text);
        return b;
    }

    private int dp(int v) {
        return (int) (v * getResources().getDisplayMetrics().density);
    }

    /**
     * Finds the address adbd is actually listening on.
     *
     * This exists because there is no correct answer to hardcode. Classic ADB
     * listened on 127.0.0.1:5555; on a modern device nothing listens there, and the
     * port depends on whether wireless debugging or "adb tcpip" was used and on
     * when. Asking the device is the only reliable method, and getting it wrong is
     * the single most common reason an agent fails to start.
     */
    private void discoverAdbd() {
        // Runs off the main thread: the probe performs thousands of connects and
        // Android forbids networking on the UI thread. Reporting on the UI thread
        // afterwards is fine and required.
        scanBtn.setEnabled(false);
        adbd.setHint("searching...");
        Probe.findAdbdAsync(found -> runOnUiThread(() -> {
            scanBtn.setEnabled(true);
            if (found == null) {
                adbd.setText("");
                adbd.setHint("no adbd found. Enable Wireless debugging, or run: adb tcpip 5557");
                toast("No adbd found on this device");
                return;
            }
            adbd.setText(found);
            toast("Found adbd at " + found);
        }));
    }

    private void onToggle() {
        Config c = new Config(
                gateway.getText().toString().trim(),
                serverName.getText().toString().trim(),
                deviceId.getText().toString().trim(),
                deviceName.getText().toString().trim(),
                adbd.getText().toString().trim());

        if (c.gateway.isEmpty()) {
            toast("Gateway address is required");
            return;
        }
        if (c.deviceId.isEmpty()) {
            toast("Device ID is required");
            return;
        }
        if (c.adbd.isEmpty()) {
            discoverAdbd();
            if (adbd.getText().length() == 0) {
                toast("No adbd address yet - enable Wireless debugging first");
                return;
            }
        }

        c.save(this);

        if (toggle.getText().toString().startsWith("Start")) {
            AgentService.start(this);
            toggle.setText("Stop");
        } else {
            AgentService.stop(this);
            toggle.setText("Start");
        }
    }

    @Override
    protected void onDestroy() {
        StatusStore.setListener(null);
        super.onDestroy();
    }

    private void requestNotificationPermission() {
        if (Build.VERSION.SDK_INT >= 33) {
            requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}, 1);
        }
    }

    private void toast(String s) {
        Toast.makeText(this, s, Toast.LENGTH_LONG).show();
    }

}