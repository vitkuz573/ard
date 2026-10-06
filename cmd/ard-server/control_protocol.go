package main

// Control-socket request and response shapes.
//
// These belong to the unix control socket, not to the operator leg: the operator leg
// speaks adb's own protocol and has no JSON frames of its own. Keeping the shapes here
// rather than next to their only readers would make the control path look like part of
// the operator protocol, which is exactly the confusion this change exists to remove.

// controlRequest is one request on the unix socket.
//
// Every op on this socket is an enrolment operation, and each requires peer uid 0. The
// stream an operator opens goes through the operator listener and registry.Open, never
// through here: a local caller must not be able to reach a device by asking the gateway
// directly, because the local caller is trusted only with enrolment.
type controlRequest struct {
	Op string `json:"op"`

	// Enrolment fields. Code identifies a pending request; CertPEM and CAPEM carry the
	// signed certificate back. They travel in the same request rather than a second
	// frame so the uid check in requireRootControl can happen before any of them is
	// looked at.
	Code    string `json:"code,omitempty"`
	CertPEM []byte `json:"cert_pem,omitempty"`
	CAPEM   []byte `json:"ca_pem,omitempty"`
}

// controlError is the reply to a request the gateway will not serve.
//
// Every error reply on this socket carries the same single field, so an unknown op and a
// refused one read the same way to whoever sent it.
type controlError struct {
	Error string `json:"error"`
}
