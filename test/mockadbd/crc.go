package mockadbd

import (
	"crypto"
)

// ADB's packet integrity rules, as implemented by AOSP. These were read out of
// the platform sources (adb.h, adb.cpp, transport.cpp) rather than inferred from
// traffic, because both rules are version-dependent and guessing produces a mock
// that either fails to authenticate or fails silently.
//
// Header layout is 24 bytes:
//
//	cmd, arg0, arg1, data_length, data_check, magic
//
// Two rules:
//
//  1. magic = command ^ 0xFFFFFFFF. It is not a constant and not a checksum: it
//     is derived from the command word, which is why observed values differ per
//     packet type (CNXN gives 0xb1a7b1bc, OPEN gives 0xb1baafb0). A device that
//     replies with a fixed sentinel is rejected.
//
//  2. data_check depends on the negotiated protocol version. At or above
//     A_VERSION_SKIP_CHECKSUM (0x01000001, December 2017) it is zero and no
//     integrity is computed at all. Below that it is the plain sum of the payload
//     bytes, NOT CRC-32 despite the field's historical name.
//
// The version is negotiated by the CNXN exchange itself, so the first packet of a
// connection carries a checksum while later ones do not.
const (
	// versionOriginal is the original protocol version.
	versionOriginal = 0x01000000
	// versionSkipChecksum disables the payload checksum.
	versionSkipChecksum = 0x01000001
)

// magicFor derives the magic field for a command word.
func magicFor(cmd uint32) uint32 { return cmd ^ 0xFFFFFFFF }

// dataCheckFor computes the data_check field for a payload under a negotiated
// version.
func dataCheckFor(payload []byte, version uint32) uint32 {
	if version >= versionSkipChecksum {
		return 0
	}
	var sum uint32
	for _, c := range payload {
		sum += uint32(c)
	}
	return sum
}

// validMagic reports whether the magic field matches its command.
func validMagic(cmd, magic uint32) bool { return magicFor(cmd) == magic }

// payloadIntact validates a payload against the data_check field. The checksum
// only exists below versionSkipChecksum, so there is nothing to verify above it.
func payloadIntact(payload []byte, version, field uint32) bool {
	if version >= versionSkipChecksum {
		return true
	}
	return dataCheckFor(payload, version) == field
}

// cryptoSHA1 names the digest adb signs its auth tokens with.
const cryptoSHA1 = crypto.SHA1
