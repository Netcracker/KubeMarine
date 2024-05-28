/*
IPIP encapsulation check scheme:

 --------           --------
| Client | ------> | Server |
 --------           --------

The Client creates and sends the IPIP packet.
The Server receives IPIP packets and tries to parse them.
If the internal IP address, destination port and message are matched, the server outputs source IP.

The packet format is the following:

 -------------------------------------------------------------------------------------------------------------------
|| Src IP | DstExt IP | IP Payload: | Src IP | DstInt IP | IP Payload: | UDP Src Port | UDP Dst Port | UDP Payload ||
 -------------------------------------------------------------------------------------------------------------------

*/
package main

import (
	"fmt"
	"net"
	"os"
	"time"
	"flag"
	"errors"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var (
	mode, msg, src, dstExt, dstInt string
	srcIP, dstExtIP, dstIntIP net.IP
	sport, dport, timeout uint
)

func customUsage() {
	fmt.Printf("Usage of %s:\n", os.Args[0])
	fmt.Printf("%s -mode client -src 192.168.0.1 -ext 192.168.0.2 -int 240.0.0.1 -sport 45455 -dport 54545 -msg Message -timeout 10\n",
	      os.Args[0])
	fmt.Printf("%s -mode server -ext 192.168.0.2 -int 240.0.0.1 -sport 45455 -dport 54545 -msg Message -timeout 3\n",
	      os.Args[0])
	fmt.Println("Where:")
	flag.PrintDefaults()
	fmt.Println("Note: Pay attention to the fact that some implementations of packet filters might includes rule that allows 'related' traffic (eg.: Security Groups implementation in OpenStack). That means the mode changing on the same host might lead to incorrect results of the check.")
}

func parseParam() error {
	flag.Usage = customUsage
	// Server or client mode. Server gets and parses IPIP pakets, and client sends IPIP pakets
	flag.StringVar(&mode, "mode", "", "Server or client mode")
	// External source IP (Src IP)
	flag.StringVar(&src, "src", "", "External source IP address")
	// External destination IP (DstExt IP)
	flag.StringVar(&dstExt, "ext", "", "External destination IP address")
	// Internal destination IP (DstInt IP)
	flag.StringVar(&dstInt, "int", "", "Internal destination IP address")
	// UDP port number (UDP Dst Port)
	flag.UintVar(&dport, "dport", 65000, "Destination UDP port")
	flag.UintVar(&sport, "sport", 53, "Source UDP port")
	flag.UintVar(&timeout, "timeout", 0, "Operation timeout")
	flag.StringVar(&msg, "msg", "", "Message as UDP payload")
	flag.Parse()
	if mode != "server" && mode != "client" {
		return errors.New("Unknown mode. It might be 'server' or 'client'")
	}
	srcIP = net.ParseIP(src)
        if srcIP == nil && mode == "client" {
		return errors.New("External source address is invalid")
	}
	dstExtIP = net.ParseIP(dstExt)
	if dstExtIP == nil {
		return errors.New("External destination address is invalid")
	}
	dstIntIP = net.ParseIP(dstInt)
	if dstIntIP == nil {
		return errors.New("Internal destination address is invalid")
	}
	if sport > 65535 {
		return errors.New("Source UDP port out of range")
	}
	if dport > 65535 {
		return errors.New("Destination UDP port out of range")
	}
	if len(msg) > 1000 {
		return errors.New("Message is too long")
	}
	return nil
}

func runSrv() {

	dstExtIPaddr := net.IPAddr{
		IP: dstExtIP,
	}
	srcUDPPort := layers.UDPPort(sport)
	dstUDPPort := layers.UDPPort(dport)
	// Listen on the external IP address. The payload protocol is IPIP
	ipConn, err := net.ListenIP("ip4:4", &dstExtIPaddr)
	if err != nil {
                fmt.Println(err)
		os.Exit(1)
	}
	defer ipConn.Close()
	decodeOpts := gopacket.DecodeOptions{
		Lazy:   false, 
		NoCopy: false,
		SkipDecodeRecovery: false,
		DecodeStreamsAsDatagrams: false,
	}
	// Set timeout
	ipConn.SetDeadline(time.Now().Add(time.Duration(timeout) * time.Second))
	buf := make([]byte, 1500)
	// Read data
	for {
		_, _, err := ipConn.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				break
			} else {
				fmt.Println(err)
				os.Exit(1)
			}
		}
		packet := gopacket.NewPacket(buf, layers.LayerTypeIPv4, decodeOpts)
		// Check second IP layer
		if packet.Layers()[0].LayerType() == layers.LayerTypeIPv4 {
			ipIntLayer := packet.Layers()[0]
			ipIntPacket := ipIntLayer.(*layers.IPv4)
			srcIntIP := fmt.Sprintf("%s", ipIntPacket.SrcIP)
			dstIntIP := fmt.Sprintf("%s", ipIntPacket.DstIP)
			// Check if destination IP matches with 'Interal IP' parameter
			if  dstInt == dstIntIP {
				// Check UDP port
				if packet.Layers()[1].LayerType() == layers.LayerTypeUDP {
					udpLayer := packet.Layers()[1]
					udpPacket := udpLayer.(*layers.UDP)
					if udpPacket.DstPort == dstUDPPort &&
					   udpPacket.SrcPort == srcUDPPort {
						payload := fmt.Sprintf("%s", packet.Layers()[1].LayerPayload())
						// Check UDP paylaod
						if payload == msg {
							fmt.Println(srcIntIP)
						}
					}
				}
			}
		}
	}
}

func runClt() {

	srcIPaddr := net.IPAddr{
		IP: srcIP,
	}
	dstExtIPaddr := net.IPAddr{
		IP: dstExtIP,
	}
	// Describe IP packet that is encapsulated in IP
	ipLayer2 := layers.IPv4{
		SrcIP:    srcIP,
		DstIP:    dstIntIP,
		Version:  4,
		IHL:      5,
		Protocol: layers.IPProtocolUDP,
	}
	// Describe UDP packet
	udpLayer := layers.UDP{
		SrcPort: layers.UDPPort(uint16(sport)),
		DstPort: layers.UDPPort(uint16(dport)),
	}
	udpLayer.SetNetworkLayerForChecksum(&ipLayer2)
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	// Searilization
	err := gopacket.SerializeLayers(buf, opts, &ipLayer2, &udpLayer, gopacket.Payload(msg))
	if err != nil {
                fmt.Println(err)
		os.Exit(1)
	}
	// Listen on the source IP. The payload protocol is IPIP
	ipConn, err := net.ListenIP("ip4:4", &srcIPaddr)
	if err != nil {
                fmt.Println(err)
		os.Exit(1)
	}
	defer ipConn.Close()
	// Send packet with one second pause
	for i := 0; i < int(timeout); i++ {
		_, err = ipConn.WriteTo(buf.Bytes(), &dstExtIPaddr)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		time.Sleep(1 * time.Second) 
	}
	fmt.Println("The packets have been sent!")
} 

func main() {
	err := parseParam()
	if err != nil {
                fmt.Println(err)
		os.Exit(1)
	}

	switch mode {
	case "server":
		runSrv()
	case "client":
		runClt()
	}
}
