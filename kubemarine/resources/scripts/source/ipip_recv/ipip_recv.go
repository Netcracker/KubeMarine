/*
The code receives IPIP packets and tries to parse them. The packet format is the following:

 -------------------------------------------------------------------------------------------------------------------
|| Src IP | DstExt IP | IP Payload: | Src IP | DstInt IP | IP Payload: | UDP Src Port | UDP Dst Port | UDP Payload ||
 -------------------------------------------------------------------------------------------------------------------
*/
package main

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"time"
	"errors"
	
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket"
)

func main() {
	if len(os.Args[1:]) < 5 {
		fmt.Println("Some parameters haven't been defined.")
		fmt.Println("Please use the following example:")
		fmt.Println("./ipip_recv 192.168.1.2 10.0.0.1 54321 UDP_Message 3")
		fmt.Println("Notice: launch needs root privileges")
		os.Exit(1)
	}
	// External IP address (DstExt IP)
	dstExtIP := net.ParseIP(os.Args[1])
	if dstExtIP == nil {
		panic("External address is invalid")
	}
	// Internal IP address (DstInt IP)
	dstInt := os.Args[2]
	if net.ParseIP(dstInt) == nil {
		panic("Internal address is invalid")
	}
	// UDP port number (UDP Dst Port)
	dport, err := strconv.Atoi(os.Args[3])
	if err != nil {
		panic(err)
	}
	dstUDPPort := layers.UDPPort(dport) 
	// Expected payload of UDP packet
	msg := os.Args[4]
	if len(msg) > 1000 {
		panic("Message is too long")
	}
	// Timeout to listen to the network interface
	timeout, err := strconv.Atoi(os.Args[5])
	if err != nil {
		panic(err)
	}
	dstExtIPaddr := net.IPAddr{
		IP: dstExtIP,
	}
	// Listen on the external IP address. The payload protocol is IPIP
	ipConn, err := net.ListenIP("ip4:4", &dstExtIPaddr)
	if err != nil {
		panic(err)
	}
	defer ipConn.Close()
	decodeOpts := gopacket.DecodeOptions{
		Lazy:   false, 
		NoCopy: false,
		SkipDecodeRecovery: false,
		DecodeStreamsAsDatagrams: false,
	}
	ipConn.SetDeadline(time.Now().Add(time.Duration(timeout) * time.Second))
	buf := make([]byte, 1500)
	// Read data
	for {
		_, _, err := ipConn.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				break
			} else {
				panic(err)
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
					if udpPacket.DstPort == dstUDPPort {
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
