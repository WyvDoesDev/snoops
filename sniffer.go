package main

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	snapshotLength int32         = 65535
	promiscuous    bool          = false
	timeout        time.Duration = -1 * time.Second
	//	err            error
	handle *pcap.Handle
)

/*
	 type Interface struct {
		Index        int          // positive integer that starts at one, zero is never used
		MTU          int          // maximum transmission unit
		Name         string       // e.g., "en0", "lo0", "eth0.100"
		HardwareAddr HardwareAddr // IEEE MAC-48, EUI-48 and EUI-64 form
		Flags        Flags        // e.g., FlagUp, FlagLoopback, FlagMulticast
	}
*/
func fileArg() {
	path := os.Args[1]
	handle, err := pcap.OpenOffline(path)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	pktNum := 0
	for packet := range packetSource.Packets() {
		pktNum++
		fmt.Println("Packet #", pktNum)
		printPacketInfo(packet)
	}
}
func noArgs() {
	var GUIDList []string
	GUIDList = append(GUIDList, "")
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	// Print device information
	//fmt.Println(devices)
	for _, device2 := range devices {

		for _, address := range device2.Addresses {
			if address.IP.To4() == nil {
			} else if address.IP == nil || address.IP.IsLoopback() {
			} else {
				fmt.Println("\nName: ", device2.Name)
				GUIDList = append(GUIDList, device2.Name)
				fmt.Println("Description: ", device2.Description)
				fmt.Println("- IP address: ", address.IP)

			}
		}
	}
	for _, GUID := range GUIDList {
		fmt.Println(GUID)
	}
	// fmt.Println(GUIDList)
	fmt.Println("Please enter what interface you want to use")
	var selected int
	fmt.Scanln(&selected)
	// fmt.Println(selected)

	if err != nil {
		log.Fatal(err)
	}

	handle, err = pcap.OpenLive(GUIDList[selected], snapshotLength, promiscuous, timeout)
	if err != nil {
		log.Fatal("OpenLive Call: ", err)
	}
	defer handle.Close()

	// Get the next packet
	packets := gopacket.NewPacketSource(
		handle, handle.LinkType()).Packets()

	for pkt := range packets {

		// fmt.Println(pkt)
		printPacketInfo(pkt)
	}

}
func main() {

	args := os.Args
	fmt.Println(args)
	if len(args) != 1 {
		fileArg()
	} else {
		noArgs()
	}

}
func printPacketInfo(packet gopacket.Packet) {
	// Let's see if the packet is an ethernet packet
	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethernetLayer != nil {
		fmt.Println("Ethernet layer detected.")
		ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
		fmt.Println("Source MAC: ", ethernetPacket.SrcMAC)
		fmt.Println("Destination MAC: ", ethernetPacket.DstMAC)
		// Ethernet type is typically IPv4 but could be ARP or other
		fmt.Println("Ethernet type: ", ethernetPacket.EthernetType)
		fmt.Println("data in bytes: ", packet.Data())
		fmt.Println("data in string: ", string(packet.Data()))
		fmt.Println()
	}

	// Let's see if the packet is IP (even though the ether type told us)
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		fmt.Println("IPv4 layer detected.")
		ip, _ := ipLayer.(*layers.IPv4)

		// IP layer variables:
		// Version (Either 4 or 6)
		// IHL (IP Header Length in 32-bit words)
		// TOS, Length, Id, Flags, FragOffset, TTL, Protocol (TCP?),
		// Checksum, SrcIP, DstIP
		fmt.Printf("From %s to %s\n", ip.SrcIP, ip.DstIP)
		fmt.Println("Protocol: ", ip.Protocol)
		fmt.Println("data in bytes: ", packet.Data())
		fmt.Println("data in string: ", string(packet.Data()))
		fmt.Println()
	}

	// Let's see if the packet is TCP
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		fmt.Println("TCP layer detected.")
		tcp, _ := tcpLayer.(*layers.TCP)

		// TCP layer variables:
		// SrcPort, DstPort, Seq, Ack, DataOffset, Window, Checksum, Urgent
		// Bool flags: FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, NS
		fmt.Printf("From port %d to %d\n", tcp.SrcPort, tcp.DstPort)
		fmt.Println("Sequence number: ", tcp.Seq)
		fmt.Println("data in bytes: ", packet.Data())
		fmt.Println("data in string: ", string(packet.Data()))
		fmt.Println()
	}

	// Iterate over all layers, printing out each layer type
	fmt.Println("All packet layers:")
	for _, layer := range packet.Layers() {
		fmt.Println("- ", layer.LayerType())
		fmt.Println()

	}

	// When iterating through packet.Layers() above,
	// if it lists Payload layer then that is the same as
	// this applicationLayer. applicationLayer contains the payload
	applicationLayer := packet.ApplicationLayer()
	if applicationLayer != nil {
		fmt.Println("Application layer/Payload found.")
		fmt.Printf("%s\n", applicationLayer.Payload())
		fmt.Println("data in bytes: ", packet.Data())
		fmt.Println("data in string: ", string(packet.Data()))
		fmt.Println()

		// Search for a string inside the payload
		if strings.Contains(string(applicationLayer.Payload()), "HTTP") {
			fmt.Println("HTTP found!")
		}
	}

	// Check for errors
	if err := packet.ErrorLayer(); err != nil {
		fmt.Println("Error decoding some part of the packet:", err)
	}
}
