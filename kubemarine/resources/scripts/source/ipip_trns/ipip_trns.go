/*
The code creates and sends the IPIP packet in the following format:

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

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func main() {
	if len(os.Args[1:]) < 6 {
		fmt.Println("Some parameters haven't been defined.")
		fmt.Println("Please use the following example:")
		fmt.Println("./ipip_trns 192.168.1.1 192.168.1.2 10.0.0.1 54321 UDP_Message 5")
		fmt.Println("Notice: launch needs root privileges")
		os.Exit(1)
	}
	// External source IP (Src IP)
	srcIP := net.ParseIP(os.Args[1])
	if srcIP == nil {
		panic("External source address is invalid")
	}
	// External destination IP (DstExt IP)
	dstExtIP := net.ParseIP(os.Args[2])
	if dstExtIP == nil {
		panic("External destination address is invalid")
	}
	// Internal destination IP (DstInt IP)
	dstIntIP := net.ParseIP(os.Args[3])
	if dstIntIP == nil {
		panic("Internal destination address is invalid")
	}
	// UDP port number (UDP Dst Port)
	dport, err := strconv.Atoi(os.Args[4])
	if err != nil {
		panic(err)
	}
	// Payload of UDP packet (UDP Payload)
	msg := []byte(os.Args[5])
	if len(msg) > 1000 {
                panic("Message is too long")
        }
	// Number of pakets that should be sent
	num, err := strconv.Atoi(os.Args[6])
	if err != nil {
		panic(err)
	}

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
		SrcPort: layers.UDPPort(53),
		DstPort: layers.UDPPort(uint16(dport)),
	}
	udpLayer.SetNetworkLayerForChecksum(&ipLayer2)
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	// Searilization
	err = gopacket.SerializeLayers(buf, opts, &ipLayer2, &udpLayer, gopacket.Payload(msg))
	if err != nil {
		panic(err)
	}
	// Listen on the source IP. The payload protocol is IPIP
	ipConn, err := net.ListenIP("ip4:4", &srcIPaddr)
	if err != nil {
		panic(err)
	}
	defer ipConn.Close()
	// Send packet with one second pause
	for i := 0; i < num; i++ {
		_, err = ipConn.WriteTo(buf.Bytes(), &dstExtIPaddr)
		if err != nil {
			panic(err)
		}
		time.Sleep(1 * time.Second) 
	}
	fmt.Printf("%v packets have been sent!\n", num)
}
