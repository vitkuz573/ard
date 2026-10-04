package dev.ard.agent;

import android.content.Context;
import java.io.File;

/**
 * Locates the agent binary.
 *
 * The agent ships inside the APK as lib/arm64-v8a/libardagent.so, so PackageManager
 * installs it into nativeLibraryDir at install time. That directory is used rather
 * than the app's own files/ directory because /data/user/<n>/<pkg>/files is mounted
 * noexec: a binary placed there fails with error=13, Permission denied. Shipping it
 * as a native library also means it is extracted once, by the platform, instead of
 * on every cold start.
 *
 * The .so suffix is only a name. execve does not inspect extensions, and the Go
 * agent is a static executable.
 */
final class AgentBinary {

    private static final String NAME = "libardagent.so";
    private static volatile File installed;

    private AgentBinary() {
    }

    static File install(Context ctx) {
        File ready = installed;
        if (ready != null && ready.canExecute()) {
            return ready;
        }
        synchronized (AgentBinary.class) {
            if (installed != null && installed.canExecute()) {
                return installed;
            }
            File dir = new File(ctx.getApplicationInfo().nativeLibraryDir);
            File bin = new File(dir, NAME);
            if (!bin.exists()) {
                throw new IllegalStateException(
                        "agent binary missing from " + dir + "; is extractNativeLibs enabled?");
            }
            if (!bin.canExecute()) {
                throw new IllegalStateException(
                        "agent binary at " + bin + " is not executable");
            }
            installed = bin;
            return bin;
        }
    }
}
