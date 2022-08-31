package main

import (
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/songgao/packets/ethernet"
	"github.com/songgao/water"
)

var (
	allowedIplist map[string]int64
)

// you can execute `nslookup mySecRet.value.zabita.ahmet.engineer ${yourserverip}`
// to trigger firewall to allow your IP address to the server
const secretDNSquery = "mySecRet.value.zabita.ahmet.engineer"

type zabitaFunc string

// This function is executed during the loading process.
func init() {
	allowedIplist = make(map[string]int64)
	log.Println("rule init done")
}

// We will store firewall rules in this function
func checkIsAllowed(f *ethernet.Frame) bool {
	decoded := []gopacket.LayerType{}
	frame := (*f)

	var tcp layers.TCP
	var udp layers.UDP
	var dns layers.DNS

	var payload gopacket.Payload
	arriveTime := time.Now().Unix()
	// 69 represents IPv4 and 96 is for IPv6
	if frame[0] == 69 {
		var ip4 layers.IPv4
		var icmp4 layers.ICMPv4
		parser4 := gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4, &ip4, &icmp4, &udp, &tcp, &dns, &payload)
		if err := parser4.DecodeLayers(frame, &decoded); err != nil {
			log.Printf("Could not decode layers: %v\n", err)
			return false
		}
		for _, layerType := range decoded {
			switch layerType {
			case layers.LayerTypeICMPv4:
				// block all ICMP packets
				log.Printf("ICMP4 is not alloved %s", ip4.SrcIP)
				return false

			case layers.LayerTypeTCP:

				// Allow all SSH conncetion
				if tcp.DstPort == 22 {
					log.Printf("new ssh client from %v:%v ", ip4.SrcIP, tcp.SrcPort)
					return true
				}

			case layers.LayerTypeUDP:
				// Allow all wireguard packets
				if udp.DstPort == 51820 {
					log.Printf("new wireguard client from %v:%v ", ip4.SrcIP, udp.SrcPort)
					return true
				}

			case layers.LayerTypeDNS:
				if string(dns.Questions[0].Name) == secretDNSquery {
					allowedIplist[ip4.SrcIP.String()] = arriveTime
					log.Printf("allow fw 100 second from %s to %s\n", ip4.SrcIP, ip4.DstIP)
					return false
				}
			}
		}

		return allowedIplist[ip4.SrcIP.String()]+100 > arriveTime

	} else if frame[0] == 96 {
		var ip6 layers.IPv6
		var icmp6 layers.ICMPv6
		var icmp6e layers.ICMPv6Echo
		var icmp6rs layers.ICMPv6RouterSolicitation
		parser6 := gopacket.NewDecodingLayerParser(layers.LayerTypeIPv6, &ip6, &icmp6, &icmp6rs, &icmp6e, &udp, &tcp, &dns, &payload)
		if err := parser6.DecodeLayers(frame, &decoded); err != nil {
			log.Printf("Could not decode layers: %v\n", err)
			return false
		}
		for _, layerType := range decoded {
			switch layerType {
			case layers.LayerTypeICMPv6:
				log.Printf("ICMP6 is not allowed %s", ip6.SrcIP)
				return false
			case layers.LayerTypeTCP:
				log.Println("TCP ", ip6.DstIP, tcp.DstPort)
				// Allow SSH
				if tcp.DstPort == 22 {
					return true
				}

			case layers.LayerTypeDNS:
				if string(dns.Questions[0].Name) == secretDNSquery {
					allowedIplist[ip6.SrcIP.String()] = arriveTime
					log.Printf("allow fw 100 second from %s to %s\n", ip6.SrcIP, ip6.DstIP)
					return false
				}
			}
		}

		return allowedIplist[ip6.SrcIP.String()]+100 > arriveTime
	}
	// not ipv4 nor ipv6
	return false
}

// This function will be executed from the main process for each packet that arrives to the system
func (z zabitaFunc) CheckFW(zabitaInterface *water.Interface, frame ethernet.Frame) {
	if checkIsAllowed(&frame) {
		zabitaInterface.Write(frame)
	}
}

// This function will be executed only once when this file loaded successfully.
func Main() {
	log.Println("Rule: allow by dns query example")
}

var ZabitaFunc zabitaFunc
