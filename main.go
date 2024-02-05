// Copyright 2024 Ian Gudger.

// Tcpdump is a Go clone of the popular tcpdump tool.
package main

import (
	"compress/gzip"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/iangudger/binary"
	"github.com/iangudger/pcap"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/unet"
)

func main() {
	iface := flag.String("i", "any", "Interface to read packets from.")
	outpath := flag.String("out", "", "Path to output file in pcap format. (Default is a randomly generated directory in /tmp)")
	maxLen := flag.Uint("len", 65536, "Max packet length.")
	helpShort := flag.Bool("h", false, "Print usage.")
	helpLong := flag.Bool("help", false, "Print usage.")
	enableGZIP := flag.Bool("gzip", false, "Compress output with gzip compression.")
	flag.Parse()

	if *helpShort || *helpLong {
		fmt.Fprintln(os.Stderr, os.Args[0], "[flags]")
		flag.PrintDefaults()
		os.Exit(1)
	}

	exit := make(chan os.Signal, 1)
	signal.Notify(exit, os.Interrupt, syscall.SIGTERM)

	if *outpath == "" {
		d, err := os.MkdirTemp("", "")
		if err != nil {
			log.Fatalln("os.MkdirTemp:", err)
		}
		*outpath = filepath.Join(d, "dump.pcap")
		if *enableGZIP {
			*outpath += ".gz"
		}
		log.Println("Saving capture to:", *outpath)
	}
	f, err := os.Create(*outpath)
	if err != nil {
		log.Fatalf("os.Create(%q): %v", *outpath, err)
	}
	defer f.Close()

	out := io.Writer(f)
	if *enableGZIP {
		w := gzip.NewWriter(out)
		defer w.Close()
		out = w
	}

	if err := writePCAPHeader(out, *maxLen); err != nil {
		log.Fatalln("writePCAPHeader:", err)
	}

	var deviceIndex int

	if *iface == "any" {
		// Zero means from all interfaces.
		deviceIndex = 0
		log.Println("Capturing from all interfaces")
	} else {
		ifc, err := net.InterfaceByName(*iface)
		if err != nil {
			log.Fatalf("net.InterfaceByName(%q): %v", *iface, err)
		}
		deviceIndex = ifc.Index
		log.Printf("Capturing interface #%d (%s)", deviceIndex, *iface)
	}

	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(hostToNet(unix.ETH_P_ALL)))
	if err != nil {
		log.Fatalln("unix.Socket(AF_PACKET, SOCK_RAW, ETH_P_ALL):", err)
	}
	s, err := unet.NewSocket(fd)
	if err != nil {
		log.Fatalln("unet.NewSocket:", err)
	}
	defer s.Close()
	go func() {
		<-exit
		log.Println("Stopping...")
		s.Close()
	}()

	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SCM_TIMESTAMP, 1); err != nil {
		log.Fatalln("unix.SetsockoptInt(SOL_SOCKET, SCM_TIMESTAMP, 1):", err)
	}

	if err := unix.Bind(fd, &unix.SockaddrLinklayer{
		Protocol: hostToNet(unix.ETH_P_ALL),
		Ifindex:  deviceIndex,
	}); err != nil {
		log.Fatalf("unix.Bind(AF_PACKET, ETH_P_ALL, %d): %v", deviceIndex, err)
	}

	packetHeaderBuf := make([]byte, 0, pcap.PacketHeaderLen)
	packetBuf := make([]byte, *maxLen)
	cmBuf := make([]byte, unix.CmsgSpace(int(binary.Size(unix.ScmTimestamping{}))))
	vec := [][]byte{packetBuf}
	var timespec unix.Timespec
	r := s.Reader(true /*blocking*/)
	for {
		r.ControlMessage = cmBuf
		n, err := r.ReadVec(vec)
		if n == 0 && err != nil {
			if err != unix.EBADF {
				log.Println("recvmsg:", err)
			}
			return
		}
		hdr, cmData, _, err := unix.ParseOneSocketControlMessage(r.ControlMessage)
		if err != nil {
			log.Println("unix.ParseOneSocketControlMessage:", err)
			continue
		}
		if hdr.Level != unix.SOL_SOCKET || hdr.Type != unix.SCM_TIMESTAMP {
			log.Println("Unknown SCM:", hdr)
			continue
		}
		binary.Unmarshal(cmData, binary.LittleEndian, &timespec)
		seconds, nanoSeconds := timespec.Unix()

		ph := pcap.PacketHeader{
			Seconds:        uint32(seconds),
			Microseconds:   uint32(nanoSeconds / int64(time.Microsecond)),
			IncludedLength: uint32(n),
			OriginalLength: uint32(n),
		}
		if ph.IncludedLength > uint32(len(packetBuf)) {
			ph.IncludedLength = uint32(len(packetBuf))
		}
		if _, err := out.Write(binary.Marshal(packetHeaderBuf, binary.LittleEndian, &ph)); err != nil {
			log.Println("Write(PacketHeader):", err)
			return
		}
		if _, err := out.Write(packetBuf[:ph.IncludedLength]); err != nil {
			log.Println("Write(packet):", err)
			return
		}
	}
}

func writePCAPHeader(w io.Writer, maxLen uint) error {
	h, err := pcap.MakeHeader(uint32(maxLen))
	if err != nil {
		return err
	}
	h.Network = pcap.LINKTYPE_ETHERNET
	if _, err := w.Write(binary.Marshal(nil, binary.LittleEndian, &h)); err != nil {
		return err
	}
	return nil
}

func hostToNet(i uint16) uint16 {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, i)
	return binary.BigEndian.Uint16(b)
}
