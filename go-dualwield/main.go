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
	"strconv"
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
	IpA    		uint32
	IpB    		uint32
	PortA  		uint16
	PortB  		uint16
	Protocol 	uint8
	_        	[3]byte // Padding to match C struct alignment
}
type flowStats struct {
	PktsAToB 		uint64
	BytesAToB		uint64
	PktsBToA		uint64
	BytesBToA		uint64
	StartTimeNs uint64
	LastTimeNs 	uint64
	TcpFlags 		uint8
	Initiator		uint8
	_ 					[6]byte // Padding for 8-byte alignment
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

func htons(port uint16) uint16 {
	return ntohs(port)
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

// getKtimeNs returns the current CLOCK_MONOTONIC time in nanoseconds, 
func getKtimeNs() uint64 {
	var ts unix.Timespec
	_ = unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	return uint64(ts.Sec)*1e9 + uint64(ts.Nsec)
}

// monitorBanlist reads a text file and syncs it with the eBPF drop map.
func monitorBanlist(filepath string, dropMap *ebpf.Map, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Cache to track what is currently in the eBPF map, saving unnecessary system calls
	knownBans := make(map[string]flowKey)

	for range ticker.C {
		file, err := os.Open(filepath)
		if err != nil {
			if !os.IsNotExist(err) { // Ignore error if file just hasn't been created yet
				log.Printf("Error opening banlist: %v", err)
			}
			continue
		}

		scanner := bufio.NewScanner(file)
		currentFileBans := make(map[string]bool)

		// Read the file and ADD new bans
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue // Skip empty lines and comments
			}

			// Expected format: Protocol,Ip_a,Port_a,Ip_b,Port_b
			parts :=strings.Split(line, ",")
			if len(parts) != 5 {
				log.Printf("Skipping invalid banlist entry (needs 5 parts): %s",line)
				continue
			}

			protocol, _ := strconv.ParseUint(parts[0], 10, 8)
			ip_a, errA := ipToUint32(parts[1])
			port_a, _ := strconv.ParseUint(parts[2], 10, 16)
			ip_b, errB := ipToUint32(parts[3])
			port_b, _ := strconv.ParseUint(parts[4], 10, 16)

			if errA != nil || errB != nil {
				continue
			}

			portNet_a := htons(uint16(port_a))
			portNet_b := htons(uint16(port_a))

			var fkey flowKey
			fkey.Protocol = uint8(protocol)

			isAToB := (ip_a < ip_b) || (ip_a == ip_b && port_a < port_b)
			if isAToB {
				fkey.IpA, fkey.IpB = ip_a, ip_b
				fkey.PortA, fkey.PortB = portNet_a, portNet_b
			} else {
				fkey.IpA, fkey.IpB = ip_b, ip_a
				fkey.PortA, fkey.PortB = portNet_b, portNet_a
			}

			currentFileBans[line] = true

			if _, exists := knownBans[line]; !exists {
				dummyValue := uint32(1)
				if err := dropMap.Put(&fkey, &dummyValue); err == nil {
					log.Printf("[QUARANTINE] blocked flow: %s", line)
					knownBans[line] = fkey
				} else {
					log.Printf("Failed to add flow '%s' to block map: %v", line, err)
				}
			}
		}
		file.Close()

		// REMOVE bans that are no longer in the text file
		for bannedString, bannedFkey := range knownBans {
			if !currentFileBans[bannedString] {
				if err := dropMap.Delete(&bannedFkey); err == nil {
					log.Printf("[UNBANNED] Removed %s from firewall drop map", bannedString)
					delete(knownBans, bannedString)
				}
			}
		}
	}
}

func getPrediction(scores []float64) int {
	bestClass := 0
	highestScore := scores[0]
	
	for classIndex, score := range scores {
		if score > highestScore {
			highestScore = score
			bestClass = classIndex
		}
	}
	return bestClass
}

var attackMap = map[int]string{
	0: "Benign",
	1: "DDoS",
	2: "Reconnaissance",
	3: "injection",
	4: "DoS",
	5: "Brute Force",
	6: "password",
	7: "xss",
	8: "Infilteration",
	9: "Exploits",
	10: "scanning",
	11: "Fuzzers",
	12: "Backdoor",
	13: "Bot",
	14: "Generic",
	15: "Analysis",
	16: "Theft",
	17: "Shellcode",
	18: "mitm",
	19: "Worms",
	20: "ransomware",
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
	
	defer func() {
		log.Println("Cleaning up: Destroying clsact qdisc to detach firewall...")
		if err := netlink.QdiscDel(qdisc); err != nil {
			log.Printf("Warning: failed to delete qdisc: %v", err)
		} else {
			log.Println("Cleanup successful. Firewall detached and maps flushed.")
		}
	}()

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

	log.Printf("Successfully attached eBPF firewall to %s", ifaceName)

	// 3. Start Banlist Monitor and setup polling for ML features
	
	banlistPath := "/root/banlist.txt"
	go monitorBanlist(banlistPath, objs.DropFlowsMap, 5*time.Second)
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

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

				nowNs := getKtimeNs()
				timeoutNs := uint64(60 * time.Second.Nanoseconds()) // 60 seconds

				// Slice to hold flows we need to delete after iterating
				var flowsToEvict []flowKey

				iterator := objs.ActiveFlows.Iterate()
				flowsFound := false

				for iterator.Next(&key, &stats) {
					if !flowsFound {
						fmt.Println("--- NEW ML BATCH ---")
						flowsFound = true
					}

					var clientIP, serverIP uint32
					var clientPort, serverPort uint16
					var outPkts, outBytes, inPkts, inBytes uint64

					if stats.Initiator == 1 {
						clientIP, serverIP = key.IpA, key.IpB
						clientPort, serverPort = key.PortA, key.PortB
						outPkts, outBytes = stats.PktsAToB, stats.BytesAToB
						inPkts, inBytes = stats.PktsBToA, stats.BytesBToA
					} else {
						clientIP, serverIP = key.IpB, key.IpA
						clientPort, serverPort = key.PortB, key.PortA
						outPkts, outBytes = stats.PktsBToA, stats.BytesBToA
						inPkts, inBytes = stats.PktsAToB, stats.BytesAToB
					}

					durationMs := (stats.LastTimeNs - stats.StartTimeNs) / 1000000

					fmt.Printf("SRC:%s:%d DST:%s:%d | PROT:%d | IN_B:%d OUT_B:%d | IN_P:%d OUT_P:%d | FLAGS:%d | DUR:%dms\n",
						intToIP(clientIP), ntohs(clientPort),
						intToIP(serverIP), ntohs(serverPort),
						key.Protocol,
						inBytes, outBytes,
						inPkts, outPkts,
						stats.TcpFlags, durationMs)

					// construct the ML feature vector
					// We use ntohs() so that the model gets the human-readable port, not the kernel byte order
					features := []float64{
						float64(ntohs(clientPort)), // L4_SRC_PORT
						float64(ntohs(serverPort)), // L4_DST_PORT
						float64(key.Protocol),      // PROTOCOL
						float64(inBytes),           // IN_BYTES
						float64(inPkts),            // IN_PKTS
						float64(outBytes),          // OUT_BYTES
						float64(outPkts),           // OUT_PKTS
						float64(stats.TcpFlags),    // TCP_FLAGS
						float64(durationMs),        // FLOW_DURATION_MILLISECONDS
					}

					scores := score(features)
					predictedClass := getPrediction(scores)

					if predictedClass == 0 {
						// fmt.Printf("[BENIGN] %s:%d -> %s:%d\n", intToIP(clientIP), ntohs(clientPort), intToIP(serverIP), ntohs(serverPort))
					} else {
						attackName, known := attackMap[predictedClass]
						if !known {
							attackName = fmt.Sprintf("Unknown_Class_%d", predictedClass)
						}

						log.Printf("[THREAT DETECTED] %s:%d -> %s:%d | Type: %s | Action: QUARANTINE",
							intToIP(clientIP), ntohs(clientPort),
							intToIP(serverIP), ntohs(serverPort),
							attackName)

						// 4. Execute the Quarantine (Surgical 5-Tuple Block)
						dummyValue := uint32(1)
						if err := objs.DropFlowsMap.Put(&key, &dummyValue); err != nil {
							log.Printf("   -> [ERROR] Failed to push quarantine to kernel: %v", err)
						}
					}

					// --- EVICTION EVALUATION ---
					shouldEvict := false

					// 1. TCP Closed Check (FIN or RST flag seen)
					if key.Protocol == 6 { 
						// TCP Flags: FIN is 0x01, RST is 0x04
						if (stats.TcpFlags & (0x01 | 0x04)) != 0 {
							shouldEvict = true
						}
					}

					// 2. Stale / Idle Timeout Check (No packets in 60 seconds)
					if (nowNs - stats.LastTimeNs) > timeoutNs {
						shouldEvict = true
					}

					// Tag for deletion
					if shouldEvict {
						flowsToEvict = append(flowsToEvict, key)
					}
				}

				// --- EXECUTE EVICTION ---
				for _, evictKey := range flowsToEvict {
					_ = objs.ActiveFlows.Delete(&evictKey)
				}

				if len(flowsToEvict) > 0 {
					log.Printf("[HOUSEKEEPING] Evicted %d closed/stale flows from kernel memory", len(flowsToEvict))
				}
			}
		}
	}()

	<-stopper
	log.Println("Detaching firewall and exiting...")
}
