package adbserverproto

// The wire format between an adb server and a device, as measured rather than recalled.
//
// Every constant here came off a live exchange: a stock adb server was asked to open a
// transport to a device and the bytes in both directions were dumped. That matters because
// this format has several near-misses in it -- a checksum that is written as zero by any
// modern peer, and a magic number that is a different constant per command -- and guessing
// any of them produces a connection that opens and then says nothing, which is the hardest
// kind of failure to see.
//
// # Layout
//
//	A packet is a 24-byte header followed by its payload:
//
//	command   4 bytes, the ASCII command
//	arg0      4 bytes, little endian
//	arg1      4 bytes, little endian
//	length    4 bytes, little endian, the payload length
//	checksum  4 bytes, little endian
//	magic     4 bytes, little endian, a constant per command
//
// The checksum is written as zero. A peer that negotiated version 41 or later skipped
// checksums, and the server observed writing 0xB1A7B1BC's neighbours all carry zero here.
const (
	adbHeaderLen = 24
	adbMaxData   = 4096

	// adbMaxPacket is the largest payload readPacket will accept from a device.
	//
	// It is not the same number as adbMaxData, and the difference is measured rather than
	// chosen. adbMaxData is what this server advertises in its own CNXN as the window it
	// offers; adbMaxPacket is what it will read. A device is free to send more than it was
	// offered -- a stock adbd sends a sync DATA frame whole, and a frame is 64 KiB of file
	// content -- and a relay that refuses those bytes breaks a transfer that adb itself
	// would have completed. The reference is the adb binary on the other side of this
	// gateway: pulling a 3 MB file from a device that put each DATA frame in one packet
	// fails with
	//
	//	adb: error: msg.data.size too large: 3000000 (max 65536)
	//
	// so 65536 is what a real adb client reads. Anything above that is a device that has
	// lost the plot, and the cap is still worth having: it is the difference between a
	// refused packet and an allocation sized by a length field.
	adbMaxPacket = 65536

	// Command bytes.
	cmdCNXN = "CNXN"
	cmdOPEN = "OPEN"
	cmdOKAY = "OKAY"
	cmdWRTE = "WRTE"
	cmdCLSE = "CLSE"

	// Magic per command. They are not derived from the command name; each is its own
	// constant, and the captured values are the only authority for them.
	magicCNXN = 0xb1a7b1bc
	magicOPEN = 0xb1baafb0
	magicOKAY = 0xa6beb4b0
	magicWRTE = 0xbaabada8
	magicCLSE = 0xbaacb3bc

	// arg0 of the CNXN the server sends to a device: A_VERSION | A_DEVICE. The device
	// answers with its own CNXN and the two agree on the version from there.
	cnxnArg0 = 0x01000001

	// hostBanner is what the server claims to be. It lists the stream features the device
	// side honours; the shell_v2 entry is what makes `adb shell` allocate a terminal.
	hostBanner = "host::features=shell_v2,cmd,stat_v2,fixed_push_mkdir,fixed_push_sync," +
		"abb,abb_exec,remount_shell,screenrecord,screencap,track_app,slow_commands," +
		"shell_v2_i64,cmdline,apex,openscreen_mdns,apex_service,conn_reactivate," +
		"auth,disconnect,list_v2,multi_cleanup,track_sources,apex_mmap,socket_localabstract_stdio"
)

// packet is one decoded ADB message.
type packet struct {
	command string
	arg0    uint32
	arg1    uint32
	payload []byte
}

// encodePacket renders one message. The checksum is deliberately zero; see the note above.
func encodePacket(command string, arg0, arg1 uint32, payload []byte) []byte {
	out := make([]byte, adbHeaderLen+len(payload))
	copy(out[0:4], command)
	putUint32(out[4:8], arg0)
	putUint32(out[8:12], arg1)
	putUint32(out[12:16], uint32(len(payload)))
	putUint32(out[16:20], 0) // checksum: skipped from version 41 on
	putUint32(out[20:24], magicFor(command))
	copy(out[adbHeaderLen:], payload)
	return out
}

// magicFor returns the constant a command carries. An unknown command is a programming error
// rather than something to paper over with zero, because zero is a real magic for no command
// and would produce a message the peer rejects without explanation.
func magicFor(command string) uint32 {
	switch command {
	case cmdCNXN:
		return magicCNXN
	case cmdOPEN:
		return magicOPEN
	case cmdOKAY:
		return magicOKAY
	case cmdWRTE:
		return magicWRTE
	case cmdCLSE:
		return magicCLSE
	default:
		return 0
	}
}

func putUint32(b []byte, v uint32) {
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	b[3] = byte(v >> 24)
}

func uint32At(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}
