package adbserverproto

// What a device says about itself in its CNXN banner, and the CNXN exchange that reads it.
//
// The banner is the only place a device states what it supports, and an operator's adb
// decides the spelling of every command it sends from that list. So the list has to reach
// the client as the device wrote it, and reading it is a protocol exchange rather than a
// string operation: it is the first packet on a connection, and by the time anybody is
// looking at a later packet it is gone.

import (
	"bufio"
	"net"
	"testing"
	"time"
)

// A banner is a semicolon-separated list of key=value fields.
//
//	device::ro.product.name=pixel_6;ro.build.type=user;features=shell_v2,cmd,stat_v2,ls_v2;
func TestBannerFeaturesReturnsTheDevicesOwnListVerbatim(t *testing.T) {
	const banner = "device::ro.product.name=pixel_6;ro.build.type=user;features=shell_v2,cmd,stat_v2,ls_v2,"
	const want = "shell_v2,cmd,stat_v2,ls_v2,"

	if got := BannerFeatures(banner); got != want {
		t.Fatalf("BannerFeatures = %q, want %q", got, want)
	}
}

// Only the field named features counts. A device whose banner carries a property of a
// similar name is not making a protocol statement about it, and treating one as the other
// would advertise a feature from a property value.
func TestBannerFeaturesIgnoresAFieldThatOnlyLooksLikeFeatures(t *testing.T) {
	const banner = "device::ro.product.features=nonsense;features=shell_v2,"
	if got := BannerFeatures(banner); got != "shell_v2," {
		t.Fatalf("BannerFeatures = %q, want %q", got, "shell_v2,")
	}
}

// A device that lists no features is a device with no features, and the caller has to be
// able to see that rather than have it turned into a failure to read a banner.
func TestBannerFeaturesIsEmptyWhenTheFieldIsAbsent(t *testing.T) {
	for _, banner := range []string{
		"device::ro.product.name=pixel_6;ro.build.type=user;",
		"device:",
		"",
	} {
		if got := BannerFeatures(banner); got != "" {
			t.Errorf("BannerFeatures(%q) = %q, want the empty string", banner, got)
		}
	}
}

// ReadDeviceBanner is the CNXN exchange, and the bytes are the ones a device answers with.
//
// The exchange, as a device sends it:
//
//	host  -> device  CNXN arg0=0x01000001 arg1=4096 "host::features=...""
//	device -> host   CNXN arg0=0x01000001 arg1=4096 "device::...;features=..."
//	host  -> device  OKAY
//
// and then the connection is closed, because the caller wanted the banner and not a
// session. The OKAY goes back because a device that has sent its CNXN waits for it before
// it will accept anything else.
func TestReadDeviceBannerReadsTheDeviceCNXNAndAcknowledgesIt(t *testing.T) {
	c, s := net.Pipe()
	go func() {
		_ = c.SetDeadline(deadlineIn(5))
		host, err := readPacketFrom(c)
		if err != nil {
			return
		}
		if host.command != cmdCNXN {
			return
		}
		const banner = "device::ro.product.name=pixel_6;features=shell_v2,cmd,stat_v2,"
		_, _ = c.Write(encodePacket(cmdCNXN, host.arg0, 1048576, []byte(banner)))
		// Then keep reading: a device that has sent its CNXN waits for the host's OKAY
		// before it accepts anything else, so a test device that stops reading hands the
		// host a write that never completes rather than a banner.
		drainPackets(c)
	}()

	got, err := ReadDeviceBanner(s)
	if err != nil {
		t.Fatalf("ReadDeviceBanner: %v", err)
	}
	const want = "device::ro.product.name=pixel_6;features=shell_v2,cmd,stat_v2,"
	if got != want {
		t.Fatalf("banner = %q, want %q", got, want)
	}
}

// Something that answers on an adbd socket announces itself as a device. A banner that does
// not say so means this is not an adbd, and saying so here is what turns "every command on
// this device fails" into "that address is not a device" -- the difference between a wrong
// port and a wrong device.
func TestReadDeviceBannerRefusesSomethingThatIsNotADevice(t *testing.T) {
	c, s := net.Pipe()
	go func() {
		_ = c.SetDeadline(deadlineIn(5))
		host, err := readPacketFrom(c)
		if err != nil {
			return
		}
		_, _ = c.Write(encodePacket(cmdCNXN, host.arg0, 1048576, []byte("emulator::port=5554")))
		drainPackets(c)
	}()

	if _, err := ReadDeviceBanner(s); err == nil {
		t.Fatal("ReadDeviceBanner accepted a banner that does not announce a device")
	}
}

// readPacketFrom reads one packet from a pipe, which is what the test device needs and what
// nothing else here has.
func readPacketFrom(c net.Conn) (packet, error) {
	return readPacket(bufio.NewReader(c))
}

// drainPackets reads until the peer goes away, which is what a device does after sending
// its banner: it waits for the host's OKAY and then for the host to hang up.
func drainPackets(c net.Conn) {
	for {
		if _, err := readPacketFrom(c); err != nil {
			return
		}
	}
}

// deadlineIn is how long a test device waits before giving up on a peer that stopped
// talking. Without it a failing expectation hangs the test rather than failing it.
func deadlineIn(seconds int) time.Time {
	return time.Now().Add(time.Duration(seconds) * time.Second)
}
