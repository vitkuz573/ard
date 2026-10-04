package dev.ard.agent;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;

/**
 * Brings the agent back after a reboot.
 *
 * Only if it was running when the device went down. Restarting an agent the
 * operator deliberately stopped would be a device that comes back on its own,
 * which is not a decision this app is entitled to make.
 */
public class BootReceiver extends BroadcastReceiver {

    @Override
    public void onReceive(Context ctx, Intent intent) {
        String action = intent == null ? null : intent.getAction();
        if (!Intent.ACTION_BOOT_COMPLETED.equals(action)
                && !Intent.ACTION_MY_PACKAGE_REPLACED.equals(action)) {
            return;
        }
        SharedPreferences p = ctx.getSharedPreferences("ard_config", Context.MODE_PRIVATE);
        if (!p.getBoolean("autostart", false)) {
            return;
        }
        AgentService.start(ctx);
    }
}