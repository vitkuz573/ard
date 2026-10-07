package dev.ard.agent;

import android.app.Application;
import android.content.Context;

/**
 * Holds the application context.
 *
 * The Application subclass is declared in the manifest, so onCreate runs before any
 * component. The declaration is the load-bearing part: without it Application.onCreate
 * never runs, the field stays null, and the first Activity dies with a
 * NullPointerException from StatusStore. This class exists only to carry the field.
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
