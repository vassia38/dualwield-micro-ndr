package main

import (
	//"bytes"
	"bufio"
	"encoding/binary"
	//"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// The //go:generate directive tells Go to run the bpf2go tool.
// It compiles the C code to little-endian eBPF (bpfel) and generates Go bindings.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel bpf dualwield_enforcer.c

// We must mirror the C struct in Go to decode the binary data coming from the perf buffer
type flowKey struct {
	SrcIP    uint32
	DstIP    uint32
	SrcPort  uint16
	DstPort  uint16
	Protocol uint8
	_        [3]byte // Padding to match C struct alignment
}
type flowStats struct {
	Packets uint64
	Bytes   uint64
}

// Helper to convert network byte order IP (uint32) to Go net.IP
func intToIP(ipInt uint32) net.IP {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, ipInt)
	return ip
}

// Helper to handle network byte order ports
func ntohs(port uint16) uint16 {
	return (port << 8) | (port >> 8)
}

// ipToUint32 converts a string IP to the uint32 format expected by the eBPF map.
func ipToUint32(ipStr string) (uint32, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return 0, fmt.Errorf("invalid IP format")
	}
	
	ip = ip.To4()
	if ip == nil {
		return 0, fmt.Errorf("not an IPv4 address")
	}

	// MT7621 is Little-Endian. The C code reads the 4-byte network IP directly 
	// into a uint32, so we must pack the bytes exactly as they appear in memory.
	return binary.LittleEndian.Uint32(ip), nil
}

// monitorBanlist reads a text file and syncs it with the eBPF drop map.
func monitorBanlist(filepath string, dropMap *ebpf.Map, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Cache to track what is currently in the eBPF map, saving unnecessary system calls
	knownBans := make(map[uint32]bool)

	for range ticker.C {
		file, err := os.Open(filepath)
		if err != nil {
			if !os.IsNotExist(err) { // Ignore error if file just hasn't been created yet
				log.Printf("Error opening banlist: %v", err)
			}
			continue
		}

		scanner := bufio.NewScanner(file)
		currentFileIPs := make(map[uint32]bool)

		// 1. Read the file and ADD new bans
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue // Skip empty lines and comments
			}

			ipInt, err := ipToUint32(line)
			if err != nil {
				log.Printf("Skipping invalid IP in banlist '%s': %v", line, err)
				continue
			}

			currentFileIPs[ipInt] = true

			// If it's a new IP, push it to the kernel
			if !knownBans[ipInt] {
				dummyValue := uint32(1)
				if err := dropMap.Put(&ipInt, &dummyValue); err != nil {
					log.Printf("Failed to block IP %s: %v", line, err)
				} else {
					log.Printf("[BANNED] Added %s to firewall drop map", line)
					knownBans[ipInt] = true
				}
			}
		}
		file.Close()

		// 2. REMOVE bans that are no longer in the text file
		for bannedIpInt := range knownBans {
			if !currentFileIPs[bannedIpInt] {
				if err := dropMap.Delete(&bannedIpInt); err != nil {
					log.Printf("Failed to unblock IP: %v", err)
				} else {
					log.Printf("[UNBANNED] Removed %s from firewall drop map", intToIP(bannedIpInt).String())
					delete(knownBans, bannedIpInt)
				}
			}
		}
	}
}

func main() {
	// 1. Load the compiled eBPF objects into the kernel
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("Failed to load eBPF objects: %v", err)
	}
	defer objs.Close()

	// 2. Setup Network Interface and Attach TC hook
	fmt.Print("Enter the interface name to attach the firewall (e.g., br-lan, eth0, eth1): ")
	// Create a reader to read from standard input (the keyboard)
	reader := bufio.NewReader(os.Stdin)
	inputName, err := reader.ReadString('\n')	
	if err != nil {
		log.Fatalf("Failed to read input: %v", err)
	}

	// Clean up the input (removes the hidden newline character from pressing Enter)
	ifaceName := strings.TrimSpace(inputName)

	if ifaceName == "" {
		log.Fatalf("Error: Interface name cannot be empty. Exiting.")
	}

	log.Printf("Attempting to attach to interface: %s", ifaceName)

	// 3. Setup Network Interface and Attach TC hook
	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		log.Fatalf("Failed to find interface '%s': %v\n(Check 'ip link' to see available interfaces)", ifaceName, err)
	}


	// Create the clsact qdisc (equivalent to: tc qdisc add dev br-lan clsact)
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	_ = netlink.QdiscAdd(qdisc) // Ignore error if it already exists

	// Attach the eBPF program (equivalent to: tc filter add dev br-lan ingress bpf da obj...)
	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Handle:    1,
			Protocol:  unix.ETH_P_ALL,
		},
		Fd:           objs.DualwieldEnforcer.FD(),
		Name:         "dualwield_enforcer",
		DirectAction: true,
	}
	if err := netlink.FilterAdd(filter); err != nil {
		log.Fatalf("Failed to attach eBPF filter: %v", err)
	}
	defer netlink.FilterDel(filter)

	log.Printf("Successfully attached eBPF firewall to %s", ifaceName)

// 3. Set up the Polling Ticker (e.g., every 3 seconds)
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	// 4. Handle interrupts for clean shutdown
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	log.Println("Polling active flows every 3 seconds... (Press Ctrl+C to exit)")

	// 5. Polling Loop
	go func() {
		for {
			select {
			case <-ticker.C:
				var key flowKey
				var stats flowStats
				
				// Create an iterator to walk through the active_flows map
				iterator := objs.ActiveFlows.Iterate()

				flowCount := 0
				for iterator.Next(&key, &stats) {
					flowCount++
					srcIP := intToIP(key.SrcIP)
					dstIP := intToIP(key.DstIP)
					srcPort := ntohs(key.SrcPort)
					dstPort := ntohs(key.DstPort)

					fmt.Printf("[FLOW] Proto: %d | %s:%d -> %s:%d | Pkts: %d, Bytes: %d\n",
						key.Protocol, srcIP, srcPort, dstIP, dstPort, stats.Packets, stats.Bytes)

					// Optional: If you want to reset the flows so you only see new traffic
					// each tick, you can delete the entry after reading it:
					// _ = objs.ActiveFlows.Delete(&key)
				}
				
				if err := iterator.Err(); err != nil {
					log.Printf("Map iteration error: %v", err)
				}
				
				if flowCount > 0 {
					fmt.Println("---------------------------------------------------")
				}
			}
		}
	}()

	banlistPath := "/root/banlist.txt"
	log.Printf("Monitoring %s for IPs to block...", banlistPath)
	go monitorBanlist(banlistPath, objs.DropIpsMap, 5*time.Second)


	<-stopper
	log.Println("Detaching firewall and exiting...")
}
