package dev.ard.agent;

import android.app.Application;
import android.content.Context;

/**
 * Holds the application context.
 *
 * The Application subclass is declared in the manifest, so onCreate runs before any
 * component. An earlier version stashed the context here but never referenced the
 * class from the manifest, so Application.onCreate never ran, the field stayed null,
 * and the first Activity died with a NullPointerException from StatusStore. The
 * declaration is the load-bearing part; this class exists only to carry the field.
 */
public class App extends Application {

    private static volatile Context context;

    @Override
    public void onCreate() {
        super.onCreate();
        context = getApplicationContext();
    }

    /** The application context, or null before onCreate. */
    static Context context() {
        return context;
    }

    /** For StatusStore, which is called from a static context. */
    static Context require() {
        Context c = context;
        if (c == null) {
            throw new IllegalStateException("application context not initialised");
        }
        return c;
    }
}
