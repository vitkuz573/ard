package dev.ard.agent;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.Inet4Address;
import java.net.NetworkInterface;
import java.util.Collections;
import java.util.Enumeration;

/**
 * Locates adbd and the address to reach it at.
 *
 * Two separate questions, and conflating them is why agents on real phones fail:
 *
 *   which port is adbd listening on  -> read from /proc, because nothing else knows
 *   which local address reaches it  -> depends on which interface adbd bound to
 *
 * A normal app cannot reach adbd at all: the platform gives apps no API for it, and
 * the socket is in the shell/adbd domain. This works because the agent process runs
 * as the app's own uid but the socket it needs is either on loopback or on an
 * interface the app can reach, and because ARD's agent is installed alongside the
 * tooling that makes that possible. Where a device forbids it entirely, discovery
 * returns nothing and the UI says so rather than inventing an address.
 */
final class Probe {

    private Probe() {
    }

    /**
     * Callback delivering the discovered address, or null.
     *
     * Asynchronous because the probe does thousands of connects and Android
     * forbids network access on the main thread. The first version called it
     * directly from the button handler; every attempt failed instantly with
     * NetworkOnMainThreadException, so the probe reported "no adbd" on a device
     * that had one, and the failure looked like a permissions problem rather than
     * a bug in the caller.
     */
    interface Result {
        void found(String hostPort);
    }

    static void findAdbdAsync(Result cb) {
        Thread t = new Thread(() -> cb.found(findAdbdAddress()), "ard-probe");
        t.setDaemon(true);
        t.start();
    }

    /** Returns "host:port" for adbd, or null when it cannot be reached. Must not run on the main thread. */
    static String findAdbdAddress() {
        String host = reachableHost();
        android.util.Log.i("ard-probe", "chosen host: " + host);
        int tried = 0;
        for (int port : candidatePorts()) {
            tried++;
            if (canConnect(host, port)) {
                android.util.Log.i("ard-probe", "FOUND " + host + ":" + port
                        + " after " + tried + " attempts");
                return host + ":" + port;
            }
            if (tried <= 8) {
                android.util.Log.i("ard-probe", "no answer on " + host + ":" + port);
            }
        }
        android.util.Log.w("ard-probe", "nothing answered after " + tried + " attempts");
        return null;
    }

    /**
     * Candidate adbd ports, in the order they should be preferred.
     *
     * These are tried by connecting rather than by reading /proc/net/tcp. A normal
     * application cannot read /proc/net: the kernel exposes only that process's
     * own sockets, so a port discovered that way is always "not found" — which is
     * how the first version of this reported no adbd on a device that plainly had
     * one. Probing by connect asks the question that actually matters and is
     * allowed.
     */
    private static int[] candidatePorts() {
        int[] known = {5555, 5557, 5558, 5559, 5560, 5561};
        // Wireless debugging picks a random high port. Trying a range is the only
        // way to find it without a privileged API, so it is bounded and cheap:
        // each attempt is a local connect that fails immediately when closed.
        java.util.List<Integer> ports = new java.util.ArrayList<>();
        for (int p : known) {
            ports.add(p);
        }
        for (int p = 37000; p <= 40200; p++) {
            ports.add(p);
        }
        int[] out = new int[ports.size()];
        for (int i = 0; i < out.length; i++) {
            out[i] = ports.get(i);
        }
        return out;
    }

    /** Prefers loopback, then any routable local address. */
    private static String reachableHost() {
        if (canConnect("127.0.0.1", 5555) || canConnect("127.0.0.1", 5557)) {
            return "127.0.0.1";
        }
        String lan = firstNonLoopbackIPv4();
        return lan != null ? lan : "127.0.0.1";
    }

    private static boolean canConnect(String host, int port) {
        try (java.net.Socket s = new java.net.Socket()) {
            s.connect(new java.net.InetSocketAddress(host, port), 400);
            android.util.Log.i("ard-probe", "connected to " + host + ":" + port
                    + " local=" + s.getLocalSocketAddress());
            return true;
        } catch (Exception e) {
            android.util.Log.i("ard-probe", "fail " + host + ":" + port + " -> "
                    + e.getClass().getSimpleName() + ": " + e.getMessage());
            return false;
        }
    }

    private static String firstNonLoopbackIPv4() {
        try {
            Enumeration<NetworkInterface> ifs = NetworkInterface.getNetworkInterfaces();
            for (NetworkInterface n : Collections.list(ifs)) {
                if (!n.isUp() || n.isLoopback()) {
                    continue;
                }
                for (Enumeration<java.net.InetAddress> a = n.getInetAddresses();
                     a.hasMoreElements(); ) {
                    java.net.InetAddress addr = a.nextElement();
                    if (addr instanceof Inet4Address
                            && !addr.isLoopbackAddress() && !addr.isLinkLocalAddress()) {
                        return addr.getHostAddress();
                    }
                }
            }
        } catch (Exception ignored) {
            // No usable interface: fall back to loopback semantics.
        }
        return null;
    }

    /** True when the agent looks able to reach the network at all. */
    static boolean hasInternet() {
        try {
            return !firstNonLoopbackIPv4().isEmpty();
        } catch (Exception e) {
            return false;
        }
    }
}