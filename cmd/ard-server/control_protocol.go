package main

import "github.com/vitkuz573/ard/internal/registry"

// Control-socket request and response shapes, shared by the control listener and the
// enrolment path.
//
// These belong to the unix control socket, not to the operator leg: the operator leg
// speaks adb's own protocol and has no JSON frames of its own. Keeping the shapes here
// rather than next to their only readers would make the control path look like part of
// the operator protocol, which is exactly the confusion this change exists to remove.

// controlRequest is one request on the unix socket.
//
// Length-prefixed JSON followed, for attach, by raw stream bytes. Framing is
// explicit rather than a stream multiplexer because there is exactly one client
// and one request type; a mux here would be structure without a reason.
type controlRequest struct {
	Op     string `json:"op"`
	Device string `json:"device,omitempty"`

	// Enrolment fields. Code identifies a pending request; CertPEM and CAPEM carry the
	// signed certificate back. They travel in the same request rather than a second
	// frame so the uid check in requireRootControl can happen before any of them is
	// looked at.
	Code    string `json:"code,omitempty"`
	CertPEM []byte `json:"cert_pem,omitempty"`
	CAPEM   []byte `json:"ca_pem,omitempty"`
}

// listResponse describes every known device, online or not.
type listResponse struct {
	Devices []registry.Device `json:"devices"`
}

// attachResponse reports which device a stream landed on.
type attachResponse struct {
	Device string `json:"device"`
	Error  string `json:"error,omitempty"`
}
