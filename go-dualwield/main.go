package main

import (
	//"bytes"
	"bufio"
	"encoding/binary"

	//"errors"
	"fmt"
	"log"
	"math"
	"net"
	"os"
	"os/signal"
	"strconv"
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
	IpA      uint32
	IpB      uint32
	PortA    uint16
	PortB    uint16
	Protocol uint8
	_        [3]byte // Padding to match C struct alignment
}
type flowStats struct {
	PktsAToB    uint64
	BytesAToB   uint64
	PktsBToA    uint64
	BytesBToA   uint64
	StartTimeNs uint64
	LastTimeNs  uint64
	TcpFlags    uint8
	Initiator   uint8
	_           [6]byte // Padding for 8-byte alignment
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

// ipToUint32 converts a string IPv4 address into the raw 4-byte layout used by the eBPF key.
// This preserves the same byte order that the kernel packet parser writes into the flow key.
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

const (
	banlistPath   = "/root/banlist.txt"
	alertsPath    = "/root/alerts.txt"
	socReviewPath = "/root/soc_review.txt"
)

var autoBanClasses = map[int]struct{}{
	1:  {}, // DDoS
	4:  {}, // DoS
	8:  {}, // Infiltration
	12: {}, // Backdoor
	13: {}, // Bot
	16: {}, // Theft
	17: {}, // Shellcode
	20: {}, // ransomware
}

// parsePortField accepts numeric ports or wildcard indicators ('*', 'any', '0').
// Returns the port as uint16 where 0 denotes a wildcard (match any port).
func parsePortField(s string) (uint16, error) {
	s = strings.TrimSpace(s)
	if s == "*" || strings.EqualFold(s, "any") || s == "0" {
		return 0, nil
	}
	v, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 0, err
	}
	return uint16(v), nil
}

// canonicalKeyString returns a normalized textual representation of a flowKey.
// Ports with value 0 are shown as '*' to indicate wildcard.
func canonicalKeyString(k flowKey) string {
	srcPort := "*"
	dstPort := "*"
	if k.PortA != 0 {
		srcPort = strconv.FormatUint(uint64(ntohs(k.PortA)), 10)
	}
	if k.PortB != 0 {
		dstPort = strconv.FormatUint(uint64(ntohs(k.PortB)), 10)
	}
	return fmt.Sprintf("%d,%s,%s,%s,%s",
		k.Protocol,
		intToIP(k.IpA).String(),
		srcPort,
		intToIP(k.IpB).String(),
		dstPort)
}

func flowKeyToBanlistLine(k flowKey) string {
	srcPort := "*"
	dstPort := "*"
	if k.PortA != 0 {
		srcPort = strconv.FormatUint(uint64(ntohs(k.PortA)), 10)
	}
	if k.PortB != 0 {
		dstPort = strconv.FormatUint(uint64(ntohs(k.PortB)), 10)
	}
	return fmt.Sprintf("%d,%s,%s,%s,%s",
		k.Protocol,
		intToIP(k.IpA).String(),
		srcPort,
		intToIP(k.IpB).String(),
		dstPort)
}

func appendUniqueLine(path, line string) error {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil
	}

	content, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	for _, existing := range strings.Split(string(content), "\n") {
		if strings.TrimSpace(existing) == line {
			return nil
		}
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := f.WriteString(line + "\n"); err != nil {
		return err
	}
	return nil
}

func persistAlert(k flowKey, attackName string) {
	timestamp := time.Now().UTC().Format(time.RFC3339)
	line := fmt.Sprintf("%s,%s,%s", timestamp, attackName, canonicalKeyString(k))
	if err := appendUniqueLine(alertsPath, line); err != nil {
		log.Printf("Failed to persist alert: %v", err)
	}
}

// persistSocReview logs cases where binary model detected malicious but multiclass model detected benign.
// These are high-confidence uncertain cases that warrant manual SOC team inspection.
func persistSocReview(k flowKey, binaryConf float64, multiclassClass int, multiclassConf float64) {
	timestamp := time.Now().UTC().Format(time.RFC3339)
	className := attackMap[multiclassClass]
	// Format: timestamp,src:port,dst:port,protocol,binary_confidence,multiclass_prediction,multiclass_confidence,reason
	reason := "[TWO-STAGE-MISMATCH] Binary classifier detected malicious but multiclass detected benign"
	line := fmt.Sprintf("%s,%s,%.4f,%s,%.4f,%s",
		timestamp,
		canonicalKeyString(k),
		binaryConf,
		className,
		multiclassConf,
		reason)
	if err := appendUniqueLine(socReviewPath, line); err != nil {
		log.Printf("Failed to persist SOC review entry: %v", err)
	}
}

func persistBanlistEntry(k flowKey) {
	line := flowKeyToBanlistLine(k)
	if err := appendUniqueLine(banlistPath, line); err != nil {
		log.Printf("Failed to persist banlist entry: %v", err)
	}
}

// returns (predictedClass, confidencePickingPredictedClass)
func predictAndConfidence(scores []float64) (int, float64) {
	n := len(scores)
	if n == 0 {
		return 0, 0.0
	}

	// check if scores already sum to ~1
	var sum float64
	for _, v := range scores {
		sum += v
	}
	const eps = 1e-6

	var probs []float64
	if math.Abs(sum-1.0) < eps && sum > 0 {
		// likely already probabilities
		probs = make([]float64, n)
		copy(probs, scores)
	} else {
		// if all non-negative, normalize by sum (vote-count style)
		allNonNeg := true
		for _, v := range scores {
			if v < 0 {
				allNonNeg = false
				break
			}
		}
		if allNonNeg && sum > 0 {
			probs = make([]float64, n)
			for i, v := range scores {
				probs[i] = v / sum
			}
		} else {
			// fallback: softmax for arbitrary real-valued scores
			max := scores[0]
			for _, v := range scores {
				if v > max {
					max = v
				}
			}
			exps := make([]float64, n)
			var expSum float64
			for i, v := range scores {
				e := math.Exp(v - max)
				exps[i] = e
				expSum += e
			}
			probs = make([]float64, n)
			for i := range exps {
				probs[i] = exps[i] / expSum
			}
		}
	}

	// argmax + confidence
	bestIdx := 0
	bestVal := probs[0]
	secondBest := 0.0
	for i, p := range probs {
		if p > bestVal {
			secondBest = bestVal
			bestVal = p
			bestIdx = i
		} else if p > secondBest && i != bestIdx {
			secondBest = p
		}
	}
	// optional margin = bestVal - secondBest
	return bestIdx, bestVal
}

// read a text file and syncs it with the eBPF drop map.
func monitorBanlist(filepath string, dropMap *ebpf.Map, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Cache to track what is currently in the eBPF map, saving unnecessary system calls
	knownBans := make(map[flowKey]struct{})

	for range ticker.C {
		file, err := os.Open(filepath)
		if err != nil {
			if !os.IsNotExist(err) { // Ignore error if file just hasn't been created yet
				log.Printf("Error opening banlist: %v", err)
			}
			continue
		}

		scanner := bufio.NewScanner(file)
		currentFileBans := make(map[flowKey]struct{})

		// Read the file and ADD new bans
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue // Skip empty lines and comments
			}

			// Expected format: Protocol,Ip_a,Port_a,Ip_b,Port_b
			parts := strings.Split(line, ",")
			if len(parts) != 5 {
				log.Printf("Skipping invalid banlist entry (needs 5 parts): %s", line)
				continue
			}

			protocol, errP := strconv.ParseUint(parts[0], 10, 8)
			ip_a, errA := ipToUint32(parts[1])
			port_a_u16, errAP := parsePortField(parts[2])
			ip_b, errB := ipToUint32(parts[3])
			port_b_u16, errBP := parsePortField(parts[4])

			if errP != nil || errA != nil || errB != nil || errAP != nil || errBP != nil {
				log.Printf("Skipping invalid banlist entry: %s", line)
				continue
			}

			portNet_a := htons(port_a_u16)
			portNet_b := htons(port_b_u16)

			var fkey flowKey
			fkey.Protocol = uint8(protocol)

			isAToB := (ip_a < ip_b) || (ip_a == ip_b && uint32(port_a_u16) < uint32(port_b_u16))
			if isAToB {
				fkey.IpA, fkey.IpB = ip_a, ip_b
				fkey.PortA, fkey.PortB = portNet_a, portNet_b
			} else {
				fkey.IpA, fkey.IpB = ip_b, ip_a
				fkey.PortA, fkey.PortB = portNet_b, portNet_a
			}

			currentFileBans[fkey] = struct{}{}

			if _, exists := knownBans[fkey]; !exists {
				dummyValue := uint32(1)
				if err := dropMap.Put(&fkey, &dummyValue); err == nil {
					log.Printf("[QUARANTINE] blocked flow: %s", canonicalKeyString(fkey))
					knownBans[fkey] = struct{}{}
				} else {
					log.Printf("Failed to add flow '%s' to block map: %v", canonicalKeyString(fkey), err)
				}
			}
		}

		if err := scanner.Err(); err != nil {
			log.Printf("Error reading banlist: %v", err)
		}

		file.Close()

		// REMOVE bans that are no longer in the text file
		for bannedFkey := range knownBans {
			if _, present := currentFileBans[bannedFkey]; !present {
				if err := dropMap.Delete(&bannedFkey); err == nil {
					log.Printf("[UNBANNED] Removed %s from firewall drop map", canonicalKeyString(bannedFkey))
					delete(knownBans, bannedFkey)
				} else {
					log.Printf("Failed to remove flow from drop map: %v", err)
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
	0:  "Benign",
	1:  "DDoS",
	2:  "Reconnaissance",
	3:  "injection",
	4:  "DoS",
	5:  "Brute Force",
	6:  "password",
	7:  "xss",
	8:  "Infilteration",
	9:  "Exploits",
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
	// Microsecond-resolution timestamps on every log line, used to measure
	// the attack-to-block latency in Chapter 6.5 (default log resolution is 1s).
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

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

	defer func() {
		if err := netlink.FilterDel(filter); err != nil {
			log.Printf("Warning: failed to remove eBPF filter: %v", err)
		}
	}()

	log.Printf("Successfully attached eBPF firewall to %s", ifaceName)

	// 3. Start Banlist Monitor and setup polling for ML features

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
				activeCount := 0 // flows present in the table at this poll (Chapter 6.4 saturation)

				for iterator.Next(&key, &stats) {
					activeCount++
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

					// ========== TWO-STAGE ANALYSIS PIPELINE ==========
					// STAGE 1: Binary Classifier (Benign vs Malicious)
					binaryScores := binaryScore(features)
					binaryPrediction, binaryConfidence := predictAndConfidence(binaryScores)

					// default eviction flag
					shouldEvict := false

					if binaryPrediction == 0 {
						// STAGE 1 -> Benign: No further analysis needed
						// Omit verbose logging unless debugging
						// fmt.Printf("[BENIGN] %s:%d -> %s:%d (confidence: %.4f)\n",
						//    intToIP(clientIP), ntohs(clientPort),
						//    intToIP(serverIP), ntohs(serverPort), binaryConfidence)
					} else {
						// stage 1 detected malicious
						log.Printf("[STAGE-1 ALERT] Binary classifier detected malicious traffic from %s:%d -> %s:%d (confidence: %.4f)",
							intToIP(clientIP), ntohs(clientPort),
							intToIP(serverIP), ntohs(serverPort),
							binaryConfidence)

						// STAGE 2: Multi-Class Classifier
						multiclassScores := multiclassScore(features)
						multiclassPrediction, multiclassConfidence := predictAndConfidence(multiclassScores)

						attackName, known := attackMap[multiclassPrediction]
						if !known {
							attackName = fmt.Sprintf("Unknown_Class_%d", multiclassPrediction)
						}

						if multiclassPrediction == 0 {
							// EDGE CASE: Binary says Malicious, but Multiclass says Benign
							// This is a high-confidence uncertain case for SOC review
							log.Printf("[TWO-STAGE-MISMATCH] Binary→Malicious (%.4f) but Multiclass→Benign (%.4f) | Flow: %s:%d → %s:%d | LOGGED FOR SOC REVIEW",
								binaryConfidence, multiclassConfidence,
								intToIP(clientIP), ntohs(clientPort),
								intToIP(serverIP), ntohs(serverPort))
							persistSocReview(key, binaryConfidence, multiclassPrediction, multiclassConfidence)
						} else {
							// Both stages agree: Malicious -> Apply quarantine logic
							log.Printf("[THREAT DETECTED] %s:%d -> %s:%d | Type: %s | Confidence: %.4f | Action: QUARANTINE",
								intToIP(clientIP), ntohs(clientPort),
								intToIP(serverIP), ntohs(serverPort),
								attackName, multiclassConfidence)

							// Apply quarantine (5-tuple or IP wildcard block for DDoS)
							dummyValue := uint32(1)

							// If this is a DDoS class, insert an IP wildcard ban to block the attacker IP
							// regardless of the destination port. The eBPF program treats port==0 as
							// a wildcard port and ip==0 as a wildcard IP in the lookup logic.
							banKey := key
							if multiclassPrediction == 1 { // DDoS
								banKey.IpA = 0
								banKey.IpB = clientIP
								banKey.PortA = 0
								banKey.PortB = 0
								log.Printf("   -> [QUARANTINE-IP] applying attacker-IP wildcard block: %s", canonicalKeyString(banKey))
							} else {
								log.Printf("   -> [QUARANTINE] applying flow block: %s", canonicalKeyString(banKey))
							}

							if err := objs.DropFlowsMap.Put(&banKey, &dummyValue); err != nil {
								log.Printf("   -> [ERROR] Failed to push quarantine to kernel: %v", err)
							} else {
								// Persist to banlist if this is an auto-ban class
								if _, auto := autoBanClasses[multiclassPrediction]; auto {
									persistBanlistEntry(banKey)
								}
								persistAlert(banKey, attackName)
							}
						}
					}

					// ========== FLOW EVICTION LOGIC ==========
					// Always check if flow should be evicted (TCP closed or idle timeout)
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

				if err := iterator.Err(); err != nil {
					log.Printf("Error iterating ActiveFlows map: %v", err)
				}

				// Flow-table occupancy snapshot (Chapter 6.4): how close the
				// 4096-entry active_flows map is to saturation under load.
				if flowsFound {
					maxEntries := objs.ActiveFlows.MaxEntries()
					log.Printf("[FLOW-TABLE] active=%d/%d (%.1f%% full)",
						activeCount, maxEntries,
						100*float64(activeCount)/float64(maxEntries))
				}

				if len(flowsToEvict) > 0 {
					for _, k := range flowsToEvict {
						if err := objs.ActiveFlows.Delete(&k); err != nil {
							log.Printf("[HOUSEKEEPING] Failed to delete flow %s: %v", canonicalKeyString(k), err)
						}
					}
					log.Printf("[HOUSEKEEPING] Evicted %d closed/stale flows from kernel memory", len(flowsToEvict))
				}
			}
		}
	}()

	<-stopper
	log.Println("Detaching firewall and exiting...")
}
