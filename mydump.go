package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"

	"bytes"
	"regexp"
	"strconv"
	"time"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	snapshot_len int32 = 65535
	handle       *pcap.Handle
	timeout      time.Duration = -1 * time.Second
	err          error
	promiscous   bool = false
	strPattern   *string
)

func main() {

	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	var interfaceName = devices[0].Name

	fileFlag := flag.String("r", "", "a string")
	interf := flag.String("i", interfaceName, "a string")
	strPattern = flag.String("s", "", "a string")

	flag.Parse()

	fmt.Println(*strPattern)

	var filter = flag.Arg(0)

	if *fileFlag != "" {
		// Opening pcap file
		if handle, err = pcap.OpenOffline(*fileFlag); err != nil {
			panic(err)
		}
	} else {
		// Opening device for Live Capture
		if handle, err = pcap.OpenLive(*interf, snapshot_len, promiscous, timeout); err != nil {
			panic(err)
		}
		fmt.Println("Reading from interface ", *interf)

	}

	if filter != "" {
		// Setting a BPF filter given by the user for capturing a subset of the traffic
		err = handle.SetBPFFilter(filter)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("Only capturing packets with filter ", filter)
	}
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		printPacketInfo(packet)
	}

}

func printPacketInfo(packet gopacket.Packet) {

	timestamp := packet.Metadata().Timestamp

	sourceMac := ""
	destinationMac := ""
	ethernetType := ""
	payload := ""
	// Checking if the packet is an ethernet packet
	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethernetLayer != nil {
		ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
		sourceMac = fmt.Sprintf("%s", ethernetPacket.SrcMAC)
		destinationMac = fmt.Sprintf("%s", ethernetPacket.DstMAC)
		ethernetTypeInInt, _ := strconv.Atoi(fmt.Sprintf("%d", ethernetPacket.EthernetType))
		ethernetType = "0x" + fmt.Sprintf("%x", ethernetTypeInInt)
		payload = fmt.Sprintf("%s", ethernetPacket.Payload)
	}

	payloadInBytes := []byte(payload)
	//For capturing only packets with matching payloads.
	if *strPattern == "" || bytes.Contains(payloadInBytes, []byte(*strPattern)) {

		packetLength := packet.Metadata().Length
		sourceIP := ""
		destinationIP := ""
		protocolType := ""

		// Checking if the packet is IP
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer != nil {
			ip, _ := ipLayer.(*layers.IPv4)

			sourceIP = fmt.Sprintf("%s", ip.SrcIP)
			destinationIP = fmt.Sprintf("%s", ip.DstIP)
			protocolType = fmt.Sprintf("%s", ip.Protocol)

		}

		sourcePort := ""
		destinationPort := ""
		tcpFlagsSet := ""

		// Checking if the packet is TCP
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)

			sourcePort = fmt.Sprintf("%s", tcp.SrcPort)
			destinationPort = fmt.Sprintf("%s", tcp.DstPort)
			if tcp.SYN {
				tcpFlagsSet += "SYN"
			}
			if tcp.RST {
				tcpFlagsSet += "RST"
			}
			if tcp.ACK {
				tcpFlagsSet += "ACK"
			}
			if tcp.FIN {
				tcpFlagsSet += "FIN"
			}
			if tcp.PSH {
				tcpFlagsSet += "PSH"
			}
			if tcp.URG {
				tcpFlagsSet += "URG"
			}
			if tcp.ECE {
				tcpFlagsSet += "ECE"
			}
			if tcp.CWR {
				tcpFlagsSet += "CWR"
			}
			if tcp.NS {
				tcpFlagsSet += "NS"
			}
		}

		// Checking if the packet is UDP
		udpLayer := packet.Layer(layers.LayerTypeUDP)
		if udpLayer != nil {
			udp, _ := udpLayer.(*layers.UDP)

			sourcePort = fmt.Sprintf("%s", udp.SrcPort)
			destinationPort = fmt.Sprintf("%s", udp.DstPort)
		}

		// Checking for errors
		if err := packet.ErrorLayer(); err != nil {
			fmt.Println("Error decoding some part of the packet:", err)
		}
		// Printing in standard Output
		fmt.Print(timestamp, " ", sourceMac, " -> ", destinationMac, " type ", ethernetType, " len ", packetLength, " ", sourceIP)

		removeTextInPorts, _ := regexp.Compile("[^0-9+]")
		if sourcePort != "" {
			sourcePort = removeTextInPorts.ReplaceAllString(sourcePort, "")
			fmt.Print(" : ", sourcePort)
		}
		if destinationIP != "" {
			fmt.Print(" -> ", destinationIP)
			if destinationPort != "" {
				destinationPort = removeTextInPorts.ReplaceAllString(destinationPort, "")
				fmt.Print(" : ", destinationPort)
			}
		}

		if strings.Contains(protocolType,"ICMP"){
			protocolType = "ICMP"
		}

		if protocolType != "UDP" && protocolType != "TCP" && protocolType != "ICMP"{
			protocolType = "OTHER"
		}

		fmt.Print(" ",protocolType, " ", tcpFlagsSet, " ", hex.Dump(payloadInBytes))

	}
}
