package dev.ard.agent;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Handler;
import android.os.Looper;

/**
 * Keeps a short rolling buffer of agent output for the UI, and the last known
 * adbd address.
 *
 * Persisted rather than held in memory because the interesting output usually
 * happens while the app is closed: an operator opens the app after something has
 * been misbehaving for an hour and needs to see what the agent said, not an empty
 * screen.
 */
final class StatusStore {

    private static final String PREFS = "ard_status";
    private static final int MAX_LINES = 400;
    private static final Handler MAIN = new Handler(Looper.getMainLooper());
    private static volatile Listener listener;

    interface Listener {
        void onStatus(String text);
    }

    private StatusStore() {
    }

    static void setListener(Listener l) {
        listener = l;
        if (l != null) {
            // A listener registered before the Application existed must not crash
            // the UI: there is simply no history to show yet.
            Context c = App.context();
            l.onStatus(c == null ? "starting" : text(c));
        }
    }

    private static Context ctx() {
        return App.require();
    }

    static void append(Context c, String line) {
        SharedPreferences p = c.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        String cur = p.getString("log", "");
        String next = cur.isEmpty() ? line : cur + "\n" + line;
        String[] parts = next.split("\n");
        if (parts.length > MAX_LINES) {
            StringBuilder sb = new StringBuilder();
            for (int i = parts.length - MAX_LINES; i < parts.length; i++) {
                sb.append(parts[i]).append('\n');
            }
            next = sb.toString();
        }
        p.edit().putString("log", next).apply();
        notify(next);
    }

    static void setAdbd(Context c, String line) {
        SharedPreferences p = c.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        p.edit().putString("adbd", line).apply();
        notify(text(c));
    }

    static String text(Context c) {
        return c.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString("log", "no output yet");
    }

    static String adbd(Context c) {
        return c.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString("adbd", "");
    }

    static void clear(Context c) {
        c.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().remove("log").apply();
        notify(text(c));
    }

    private static void notify(String t) {
        Listener l = listener;
        if (l != null) {
            MAIN.post(() -> l.onStatus(t));
        }
    }
}