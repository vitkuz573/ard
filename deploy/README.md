# Deployment notes

## Why RestrictFileSystems is not used

`RestrictFileSystems=` is implemented with BPF, and under `NoNewPrivileges=yes`
the sandbox cannot create the inner BPF map. On this kernel the unit fails at
step BPF and crash-loops:

    bpf-restrict-fs: Failed to create inner BPF map: Operation not permitted
    ard-server.service: Failed at step BPF spawning ...: Operation not permitted

It was removed rather than worked around with `CAP_BPF`, because granting a
capability to the gateway in order to restrict it is a bad trade. The protections
that apply without BPF are kept: `ProtectSystem=strict`, `ReadOnlyPaths`,
`CapabilityBoundingSet=`, `AmbientCapabilities=`, `SystemCallFilter`, and
`PrivateDevices`.

Verify the resulting posture with `systemd-analyze security ard-server.service`.

## Port exposure

Three TCP ports are opened. Two require mutual TLS against separate roots:

    7000/tcp   device listener   trusts the device CA
    7100/tcp   operator listener trusts the operator CA

The third, 7200, is the enrolment listener and is different in kind: it accepts a
peer with no client certificate, because a device has none until it is enrolled. It
can do nothing on its own — it stores a certificate request and waits for a human
holding the CA.

Nothing that speaks the raw ADB protocol is ever exposed on a network interface,
and nothing serves an unauthenticated ADB transport at all. The gateway answers
adb's server protocol only after mutual TLS has identified an operator and that
operator's name has been found in the ACL, and every device question is then
answered from that operator's own grants. `ard-connect` publishes its one port on
the operator's own machine, so there is no gateway-side port for it at all.

An operator's `adb forward` does bind a port on this host, and it needs no firewall
rule: the gateway binds it on `127.0.0.1`, so it is reachable from the host and from
nothing else. `adb reverse` reaches the same loopback from the other end. A forward
outlives the adb connection that created it, so a host left with unexpected bound
ports is usually an operator's forward still held — `adb forward --list` names it,
`adb forward --remove-all` releases it.

Devices and operators both dial in. That is not incidental — devices sit behind
NAT, often carrier-grade NAT, so the gateway can never connect to them.

## First device enrollment

    ard-ca device -dir /etc/ard/pki -id <uuid>

then add the UUID to `ARD_DEVICES` in `/etc/ard/ard-server.env` and grant it in
`/etc/ard/operators.yaml`, then restart:

    systemctl restart ard-server

`scripts/deploy.sh --rotate-device <uuid>` does the PKI half of this and preserves
the existing list.

The order of `ARD_DEVICES` carries no meaning: `adb` asks the gateway which devices
exist and is answered with UUIDs. Appending is still the right habit — the deploy preserves
the list and only adds to it — and reordering does not invalidate any saved serial.
