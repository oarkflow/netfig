package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/phuslu/iploc" // added for IP to country lookup
)

type Data any

type Node interface {
	Run(ctx context.Context, wg *sync.WaitGroup)
}

func getInterfaceType(iface net.Interface) string {
	name := strings.ToLower(iface.Name)
	switch runtime.GOOS {
	case "darwin":
		if iface.Name == "en0" || iface.Name == "en1" {
			return "Wi-Fi"
		}
		if strings.Contains(name, "eth") {
			return "Ethernet"
		}
	default:
		if strings.Contains(name, "wlan") || strings.Contains(name, "wifi") {
			return "Wi-Fi"
		} else if strings.Contains(name, "eth") || strings.HasPrefix(name, "en") {
			return "Ethernet"
		}
	}
	return "Unknown"
}

type NetInterfaceNode struct {
	config map[string]any
	out    chan Data
}

func NewNetInterfaceNode(config map[string]any, out chan Data) *NetInterfaceNode {
	return &NetInterfaceNode{
		config: config,
		out:    out,
	}
}

func (n *NetInterfaceNode) Run(ctx context.Context, wg *sync.WaitGroup) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		log.Println("[NetInterfaceNode] Listing network interfaces...")
		interfaces, err := net.Interfaces()
		if err != nil {
			log.Printf("[NetInterfaceNode] Error listing interfaces: %v", err)
			return
		}
		if len(interfaces) == 0 {
			log.Println("[NetInterfaceNode] No interfaces found.")
			return
		}
		log.Println("[NetInterfaceNode] Found interfaces:")
		for i, iface := range interfaces {
			ifType := getInterfaceType(iface)
			log.Printf("  [%d] %s (Type: %s, Flags: %s)", i, iface.Name, ifType, iface.Flags.String())
		}
		var selected string
		if dev, ok := n.config["device"].(string); ok && dev != "" {
			selected = dev
			log.Printf("[NetInterfaceNode] Using device from config: %s", selected)
		} else {
			inputChan := make(chan string, 1)
			go func() {
				reader := bufio.NewReader(os.Stdin)
				fmt.Print("Enter the number of the interface to use: ")
				input, err := reader.ReadString('\n')
				if err != nil {
					log.Printf("[NetInterfaceNode] Error reading input: %v", err)
					inputChan <- ""
					return
				}
				inputChan <- strings.TrimSpace(input)
			}()
			select {
			case input := <-inputChan:
				if input == "" {
					log.Println("[NetInterfaceNode] No input received.")
					return
				}
				idx, err := strconv.Atoi(input)
				if err != nil || idx < 0 || idx >= len(interfaces) {
					log.Printf("[NetInterfaceNode] Invalid selection: %v", err)
					return
				}
				selected = interfaces[idx].Name
			case <-ctx.Done():
				log.Println("[NetInterfaceNode] Context cancelled while waiting for user input.")
				return
			}
		}
		if selected == "" {
			log.Println("[NetInterfaceNode] No suitable interface selected.")
			return
		}
		log.Printf("[NetInterfaceNode] Selected interface: %s", selected)
		select {
		case n.out <- selected:
			log.Printf("[NetInterfaceNode] Sent selected device (%s) downstream", selected)
		case <-ctx.Done():
			log.Println("[NetInterfaceNode] Context cancelled before sending device name.")
			return
		}
	}()
}

type PacketCaptureNode struct {
	in     chan Data
	out    chan Data
	config map[string]any
}

func NewPacketCaptureNode(in, out chan Data, config map[string]any) *PacketCaptureNode {
	return &PacketCaptureNode{
		in:     in,
		out:    out,
		config: config,
	}
}

func (p *PacketCaptureNode) Run(ctx context.Context, wg *sync.WaitGroup) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		var device string
		select {
		case d := <-p.in:
			if devName, ok := d.(string); ok {
				device = devName
			} else {
				log.Println("[PacketCaptureNode] Invalid device name received")
				return
			}
		case <-ctx.Done():
			log.Println("[PacketCaptureNode] Context cancelled before receiving device name.")
			return
		}
		if dev, ok := p.config["device"].(string); ok && dev != "" {
			device = dev
		}
		log.Printf("[PacketCaptureNode] Starting packet capture on %s", device)
		snaplen := int32(1600)
		promisc := true
		timeout := pcap.BlockForever
		handle, err := pcap.OpenLive(device, snaplen, promisc, timeout)
		if err != nil {
			log.Printf("[PacketCaptureNode] Error opening device %s: %v", device, err)
			return
		}
		defer handle.Close()
		// Set BPF filter if provided in config
		if f, ok := p.config["filter"].(string); ok && f != "" {
			if err := handle.SetBPFFilter(f); err != nil {
				log.Printf("[PacketCaptureNode] Error setting filter %s: %v", f, err)
				return
			}
			log.Printf("[PacketCaptureNode] Applied BPF filter: %s", f)
		}
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		packetChan := packetSource.Packets()
		for {
			select {
			case packet, ok := <-packetChan:
				if !ok {
					log.Println("[PacketCaptureNode] Packet channel closed")
					return
				}
				ipLayer := packet.Layer(layers.LayerTypeIPv4)
				if ipLayer == nil {
					continue
				}
				ip, _ := ipLayer.(*layers.IPv4)
				srcIP := ip.SrcIP.String()
				dstIP := ip.DstIP.String()

				// New: IP to DNS resolution for source and destination IPs
				srcDomain, dstDomain := "", ""
				if names, err := net.LookupAddr(srcIP); err == nil && len(names) > 0 {
					srcDomain = strings.TrimSuffix(names[0], ".")
				}
				if names, err := net.LookupAddr(dstIP); err == nil && len(names) > 0 {
					dstDomain = strings.TrimSuffix(names[0], ".")
				}

				// New: IP to country lookup using github.com/phuslu/iploc
				srcCountry, dstCountry := "Unknown", "Unknown"
				if country := iploc.Country(ip.SrcIP); country != "" {
					srcCountry = country
				}
				if country := iploc.Country(ip.DstIP); country != "" {
					dstCountry = country
				}

				txRx := "Rx"
				if strings.HasPrefix(srcIP, "192.168") || strings.HasPrefix(srcIP, "10.") {
					txRx = "Tx"
				}
				apiInfo := ""
				if tlsLayer := packet.Layer(layers.LayerTypeTLS); tlsLayer != nil {
					tls, _ := tlsLayer.(*layers.TLS)
					apiInfo = fmt.Sprintf("TLS Packet: HandshakeCount=%d", len(tls.Handshake))
					for idx, hs := range tls.Handshake {
						apiInfo += fmt.Sprintf(" | Handshake[%d]: Type=%d, Length=%d, Data=%x", idx, hs.ContentType, hs.Length, hs)
					}
					if app := packet.ApplicationLayer(); app != nil {
						apiInfo += " | Encrypted Payload: " + fmt.Sprintf("%x", app.Payload())
					}
				} else if appLayer := packet.ApplicationLayer(); appLayer != nil {
					payload := appLayer.Payload()
					if len(payload) > 0 {
						hexPayload := fmt.Sprintf("%x", payload)
						textPayload := string(payload)
						if strings.HasPrefix(textPayload, "GET") || strings.HasPrefix(textPayload, "POST") {
							apiInfo = "Request Data: " + textPayload + " | Hex: " + hexPayload
						} else if strings.HasPrefix(textPayload, "HTTP/") {
							apiInfo = "Response Data: " + textPayload + " | Hex: " + hexPayload
						} else {
							apiInfo = "App Layer Data:  | Hex: " + hexPayload
						}
					}
				}
				// Update summary to include IP and corresponding DNS domain (if available)
				srcInfo := srcIP
				if srcDomain != "" {
					srcInfo += " (" + srcDomain + ")"
				}
				srcInfo += " [Country: " + srcCountry + "]"
				dstInfo := dstIP
				if dstDomain != "" {
					dstInfo += " (" + dstDomain + ")"
				}
				dstInfo += " [Country: " + dstCountry + "]"
				summary := fmt.Sprintf("Packet %s | Src: %s, Dst: %s", txRx, srcInfo, dstInfo)
				if apiInfo != "" {
					summary += fmt.Sprintf(" | %s", apiInfo)
				}
				summary = fmt.Sprintf("%s at %s", summary, packet.Metadata().Timestamp.Format(time.RFC3339))
				select {
				case p.out <- summary:
				case <-ctx.Done():
					log.Println("[PacketCaptureNode] Context cancelled during packet forwarding")
					return
				}
			case <-ctx.Done():
				log.Println("[PacketCaptureNode] Context cancelled, stopping packet capture")
				return
			}
		}
	}()
}

type LoggerNode struct {
	in     chan Data
	config map[string]any
}

func NewLoggerNode(in chan Data, config map[string]any) *LoggerNode {
	return &LoggerNode{
		in:     in,
		config: config,
	}
}

func (l *LoggerNode) Run(ctx context.Context, wg *sync.WaitGroup) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		outputType := "stdout"
		if ot, ok := l.config["outputType"].(string); ok && ot != "" {
			outputType = ot
		}
		for {
			select {
			case data, ok := <-l.in:
				if !ok {
					log.Println("[LoggerNode] Input channel closed, exiting")
					return
				}
				msg := fmt.Sprintf("[LoggerNode] %v", data)
				if outputType == "stderr" {
					fmt.Fprintln(os.Stderr, msg)
				} else {
					fmt.Println(msg)
				}
			case <-ctx.Done():
				log.Println("[LoggerNode] Context cancelled, stopping logger")
				return
			}
		}
	}()
}

func main() {
	deviceFlag := flag.String("device", "", "Name of the network interface to use. If empty, you will be prompted.")
	outputFlag := flag.String("output", "stdout", "Output sink: stdout or stderr.")
	filterFlag := flag.String("filter", "", "BPF filter for packet capture (optional).")
	flag.Parse()
	log.Println("Starting Pipeline DAG...")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigChan
		log.Printf("Received signal: %v. Shutting down...", sig)
		cancel()
	}()
	deviceCh := make(chan Data, 1)
	packetCh := make(chan Data, 100)
	var wg sync.WaitGroup
	netConfig := map[string]any{
		"device": *deviceFlag,
	}
	packetConfig := map[string]any{
		"filter": *filterFlag,
	}
	loggerConfig := map[string]any{
		"outputType": *outputFlag,
	}
	netNode := NewNetInterfaceNode(netConfig, deviceCh)
	packetNode := NewPacketCaptureNode(deviceCh, packetCh, packetConfig)
	loggerNode := NewLoggerNode(packetCh, loggerConfig)
	netNode.Run(ctx, &wg)
	packetNode.Run(ctx, &wg)
	loggerNode.Run(ctx, &wg)
	wg.Wait()
	log.Println("Pipeline terminated gracefully.")
}
