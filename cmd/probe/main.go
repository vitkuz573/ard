// Command probe sits between a real adb and a mock device, logs both directions, and can
// append bytes to whatever the device sends.
//
// It exists because tracing from inside the mock was not enough. Tracing shows what the
// device did, and for a long time the device was doing the right thing -- the stall was in
// how many replies adb expected and how long it waits between them, which is invisible from
// one side. A proxy sees the exchange as adb sees it, and it can be made to lie: append a
// reply, change a mode field, and watch whether adb moves. That turned "adb blocks" into a
// question with an experiment attached.
//
// Usage:
//
//	probe -listen 127.0.0.1:5601 -target 127.0.0.1:5600
//	adb connect 127.0.0.1:5601
//
//	# append bytes to the device's output once 64 KiB have passed device to host
//	probe -inject 4f4b4159 -after 65536 ...
//
// It is a diagnostic tool, not part of the shipped product.
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
	"time"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:5601", "where adb connects")
	target := flag.String("target", "127.0.0.1:5555", "the mock device")
	inject := flag.String("inject", "", "hex bytes appended to each device->adb message")
	after := flag.Int("after", 0, "inject only once this many bytes have passed device->adb")
	flag.Parse()

	var extra []byte
	if *inject != "" {
		var err error
		extra, err = parseHex(*inject)
		if err != nil {
			fmt.Fprintln(os.Stderr, "probe: bad hex:", err)
			os.Exit(2)
		}
	}

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		fmt.Fprintln(os.Stderr, "probe: listen:", err)
		os.Exit(1)
	}
	fmt.Printf("probe: %s -> %s\n", *listen, *target)

	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go handle(c, *target, extra, int64(*after))
	}
}

func handle(client net.Conn, target string, extra []byte, after int64) {
	defer client.Close()
	up, err := net.Dial("tcp", target)
	if err != nil {
		fmt.Fprintln(os.Stderr, "probe: dial:", err)
		return
	}
	defer up.Close()

	var toDevice int64
	var toHost int64
	injected := false
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := up.Read(buf)
			if n > 0 {
				toDevice += int64(n)
				log("adb ->dev", buf[:n])
				if _, werr := client.Write(buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()
	buf := make([]byte, 4096)
	for {
		n, err := client.Read(buf)
		if n > 0 {
			chunk := append([]byte(nil), buf[:n]...)
			log("dev ->adb", chunk)
			toHost += int64(n)
			if !injected && len(extra) > 0 && toHost >= after {
				injected = true
				chunk = append(chunk, extra...)
				log("probe INJECT", extra)
			}
			if _, werr := up.Write(chunk); werr != nil {
				return
			}
		}
		if err != nil {
			fmt.Printf("probe: %s ended: %v\n", time.Now().Format("15:04:05.000"), err)
			return
		}
	}
}

func log(dir string, b []byte) {
	words := ""
	for i := 0; i+4 <= len(b); i += 4 {
		w := binary.LittleEndian.Uint32(b[i : i+4])
		if printable(w) {
			words += fmt.Sprintf(" %q", string([]byte{byte(w), byte(w >> 8), byte(w >> 16), byte(w >> 24)}))
		}
	}
	fmt.Printf("%s %s len=%d%s\n", time.Now().Format("15:04:05.000"), dir, len(b), words)
}

func printable(w uint32) bool {
	for _, c := range []byte{byte(w), byte(w >> 8), byte(w >> 16), byte(w >> 24)} {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}

func parseHex(s string) ([]byte, error) {
	if len(s)%2 != 0 {
		return nil, fmt.Errorf("odd length")
	}
	out := make([]byte, len(s)/2)
	for i := 0; i < len(out); i++ {
		var v byte
		for _, c := range []byte{s[i*2], s[i*2+1]} {
			v <<= 4
			switch {
			case c >= '0' && c <= '9':
				v |= c - '0'
			case c >= 'a' && c <= 'f':
				v |= c - 'a' + 10
			case c >= 'A' && c <= 'F':
				v |= c - 'A' + 10
			default:
				return nil, fmt.Errorf("bad hex digit %q", c)
			}
		}
		out[i] = v
	}
	return out, nil
}
