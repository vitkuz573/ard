package dev.ard.agent;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.os.IBinder;

/**
 * Runs the agent as a foreground service.
 *
 * A foreground service rather than a background process because the agent is
 * useless the moment Android kills it, and it will: the device is expected to sit
 * for days behind NAT and re-dial on every network change. A visible,
 * non-dismissible notification is the price, and it is the honest one, because it
 * also tells whoever is holding the phone that this device is remotely reachable.
 */
public class AgentService extends Service {

    public static final String CHANNEL_ID = "ard_agent";
    public static final String EXTRA_ACTION = "action";
    public static final String ACTION_START = "start";
    public static final String ACTION_STOP = "stop";

    private Process process;
    private Thread logPump;

    public static void start(Context ctx) {
        Intent i = new Intent(ctx, AgentService.class);
        i.putExtra(EXTRA_ACTION, ACTION_START);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            ctx.startForegroundService(i);
        } else {
            ctx.startService(i);
        }
    }

    public static void stop(Context ctx) {
        Intent i = new Intent(ctx, AgentService.class);
        i.putExtra(EXTRA_ACTION, ACTION_STOP);
        ctx.startService(i);
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        String action = intent == null ? ACTION_START : intent.getStringExtra(EXTRA_ACTION);
        if (ACTION_STOP.equals(action)) {
            stopAgent();
            stopSelf();
            return START_NOT_STICKY;
        }

        createChannel();
        startForeground(1, buildNotification("Connecting to the gateway"));
        if (process == null) {
            startAgent();
        }
        // Restart if Android reclaims the process: the whole point is that the
        // device re-dials without a human present.
        return START_STICKY;
    }

    private void startAgent() {
        Config cfg = Config.load(this);
        try {
            String bin = AgentBinary.install(this).getAbsolutePath();
            java.io.File certDir = Config.certDir(this);
            String[] argv = cfg.argv(this, bin);
            android.util.Log.i("ard-agent", "argv: " + java.util.Arrays.toString(argv));
            android.util.Log.i("ard-agent", "cwd: " + certDir.getAbsolutePath());
            ProcessBuilder pb = new ProcessBuilder(argv);
            pb.directory(certDir);
            pb.redirectErrorStream(true);
            process = pb.start();

            final String tag = "ard-agent";
            logPump = new Thread(() -> {
                try (java.io.BufferedReader r = new java.io.BufferedReader(
                        new java.io.InputStreamReader(process.getInputStream()))) {
                    String line;
                    while ((line = r.readLine()) != null) {
                        android.util.Log.i(tag, line);
                        StatusStore.append(getApplicationContext(), line);
                        // The agent reports the adbd address it settled on, which is
                        // the value an operator most often needs and cannot infer
                        // from outside the phone.
                        if (line.contains(" adbd ")) {
                            StatusStore.setAdbd(getApplicationContext(), line);
                        }
                    }
                } catch (Exception ignored) {
                    // The agent exiting is reported by the exit handler below.
                }
            }, "ard-log");
            logPump.setDaemon(true);
            logPump.start();

            new Thread(() -> {
                try {
                    process.waitFor();
                    StatusStore.append(getApplicationContext(), "agent exited with "
                            + process.exitValue());
                } catch (InterruptedException ignored) {
                    Thread.currentThread().interrupt();
                }
            }, "ard-wait").start();

            StatusStore.append(getApplicationContext(), "agent started: " + cfg.summary());
        } catch (Exception e) {
            StatusStore.append(getApplicationContext(), "failed to start agent: " + e);
        }
    }

    private void stopAgent() {
        if (process != null) {
            process.destroy();
            process = null;
        }
        if (logPump != null) {
            logPump.interrupt();
            logPump = null;
        }
        stopForeground(true);
    }

    private void createChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
            return;
        }
        NotificationManager nm = getSystemService(NotificationManager.class);
        if (nm.getNotificationChannel(CHANNEL_ID) != null) {
            return;
        }
        NotificationChannel ch = new NotificationChannel(
                CHANNEL_ID, "ARD agent", NotificationManager.IMPORTANCE_LOW);
        ch.setDescription("Keeps this device reachable by the ARD gateway");
        nm.createNotificationChannel(ch);
    }

    private Notification buildNotification(String body) {
        Notification.Builder b;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            b = new Notification.Builder(this, CHANNEL_ID);
        } else {
            b = new Notification.Builder(this);
        }
        return b.setContentTitle("ARD agent")
                .setContentText(body)
                .setSmallIcon(android.R.drawable.stat_sys_upload_done)
                .setOngoing(true)
                .build();
    }

    @Override
    public void onDestroy() {
        stopAgent();
        super.onDestroy();
    }

    @Override
    public void onTaskRemoved(Intent rootIntent) {
        // Swiping the app away must not silently unregister the device; the
        // operator would see a device that vanished with no explanation.
        super.onTaskRemoved(rootIntent);
    }
}