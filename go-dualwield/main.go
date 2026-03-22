package main

import (
	//"bytes"
	"encoding/binary"
	//"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"
	//"github.com/cilium/ebpf/perf"
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

func main() {
	// 1. Load the compiled eBPF objects into the kernel
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("Failed to load eBPF objects: %v", err)
	}
	defer objs.Close()

	// 2. Setup Network Interface and Attach TC hook
	ifaceName := "br-lan"
	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		log.Fatalf("Failed to find interface %s: %v", ifaceName, err)
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
	<-stopper
	log.Println("Detaching firewall and exiting...")
}
