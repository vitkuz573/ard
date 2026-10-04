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

Nothing that speaks the raw ADB protocol is ever exposed on a network interface.
`ard-proxy` binds `127.0.0.1` only, because the port it serves is an
unauthenticated ADB transport: anyone who can reach it has full control of the
device behind it.

Devices and operators both dial in. That is not incidental — devices sit behind
NAT, often carrier-grade NAT, so the gateway can never connect to them.

## First device enrollment

    ard-ca device -dir /etc/ard/pki -id <uuid>

then add the UUID to `ARD_DEVICES` in `/etc/ard/ard-server.env` and grant it in
`/etc/ard/operators.yaml`, then restart:

    systemctl restart ard-server ard-proxy

Ports are assigned from the order of `ARD_DEVICES`, so reordering that list
changes existing serials. Treat it as append-only.
