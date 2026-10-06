package adbserverproto

// Reading what a device says about itself.
//
// A device announces itself in the CNXN it sends when a transport is opened: a
// semicolon-separated banner of `key=value` fields, one of which is `features`.
// That list is what the device can actually do, so it is the only honest source
// for what a client should be told the device supports -- an operator's adb picks
// the spelling of every command it sends from that list, and a list that does not
// match the device produces a client on a path the device cannot serve.
//
// The read is a whole CNXN exchange and then a close. A device's CNXN cannot be
// picked out of a stream later: it is the first packet on that connection and it
// is gone by the time anybody looks. Asking once, before anything has been told to
// anybody, is what makes the answer a fact about the device rather than a constant
// in this file.

import (
	"bufio"
	"fmt"
	"net"
	"strings"
)

// BannerFeatures returns the device's feature list from a CNXN banner.
//
// A banner looks like
//
//	device::ro.product.name=pixel_6;features=shell_v2,cmd,stat_v2,...;
//
// and the value runs to the next semicolon or to the end of the banner. Only the
// exact field name counts: a banner carries any number of other fields, and one
// of them on some devices is named `ro.product.features`, so a loose match would
// turn a property into a protocol statement.
//
// An absent field yields the empty string rather than an error. A device that
// lists no features is a device with no features, and the caller has to be able to
// see that rather than have it turned into a failure to interpret a banner.
//
// The value is returned as it was sent, trailing separator and all. A client
// parses it by splitting on commas, and a real adb server hands the device's own
// bytes to its client rather than reassembling a list of its own: a list rebuilt
// here could differ from the device's in an empty trailing field, and the diff
// would be invisible until a command chose the wrong path because of it.
func BannerFeatures(banner string) string {
	for _, field := range strings.Split(banner, ";") {
		key, value, found := strings.Cut(field, "=")
		if found && key == "features" {
			return value
		}
	}
	return ""
}

// ReadDeviceBanner performs the CNXN exchange with a device and returns its banner.
//
// This is the device side of what a transport switch does for an operator's
// stream, and it stops there: the caller wanted the banner rather than a session,
// so the connection is closed as soon as the banner has been read. The OKAY that
// completes the exchange is sent first, because a device that has sent its CNXN
// waits for it before it accepts anything else.
func ReadDeviceBanner(conn net.Conn) (string, error) {
	br := bufio.NewReader(conn)
	if _, err := conn.Write(encodePacket(cmdCNXN, cnxnArg0, adbMaxData, []byte(hostBanner))); err != nil {
		return "", fmt.Errorf("send CNXN: %w", err)
	}
	reply, err := readPacket(br)
	if err != nil {
		return "", fmt.Errorf("read device CNXN: %w", err)
	}
	if reply.command != cmdCNXN {
		return "", fmt.Errorf("device answered %q where CNXN was expected", reply.command)
	}
	if _, err := conn.Write(encodePacket(cmdOKAY, cnxnArg0, adbMaxData, nil)); err != nil {
		return "", fmt.Errorf("acknowledge CNXN: %w", err)
	}
	banner := string(reply.payload)
	// Anything answering on an adbd socket announces itself as a device, and a
	// banner that does not say so means this is not an adbd. Saying so here turns
	// "every command fails" into "this address is not a device", which is the
	// difference between a wrong port and a wrong device.
	if !strings.HasPrefix(banner, "device:") {
		return "", fmt.Errorf("banner %q does not announce a device", banner)
	}
	return banner, nil
}
