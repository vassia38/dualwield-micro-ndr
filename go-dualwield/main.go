package main

import (
	//"bytes"
	"bufio"
	"encoding/binary"

	//"errors"
	"flag"
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

// lpmV4Key mirrors struct lpm_v4_key in the eBPF program: a prefix length plus
// the four address bytes in network order. Addr uses the same raw little-endian
// layout as the flowKey IPs (the value the kernel reads straight from the packet).
type lpmV4Key struct {
	Prefixlen uint32
	Addr      uint32
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
	banlistPath     = "/root/banlist.txt"
	alertsPath      = "/root/alerts.txt"
	socReviewPath   = "/root/soc_review.txt"
	whitelistPath   = "/root/whitelist.txt"
	threatIntelPath = "/root/threat_intel.txt"
)

// allowlistNets holds the trusted networks (auto-detected seeds + user file),
// used by the userspace ban guard. Set once at startup by loadAllowlist before
// any goroutine reads it, so no locking is needed.
var allowlistNets []*net.IPNet

// Flows already written to alerts.txt / soc_review.txt during their current
// lifetime. Re-scoring the same active flow at consecutive polls must not
// append a duplicate line: appendUniqueLine cannot catch this because every
// line carries a fresh timestamp and is therefore unique. These sets are
// cleared when the flow is evicted (see the eviction loop), so a flow that
// closes and reappears with the same 5-tuple is logged again. Accessed only
// from the polling goroutine, so no locking is needed.
var (
	alertedFlows     = make(map[flowKey]struct{})
	socReviewedFlows = make(map[flowKey]struct{})
	// lastScoredPkts (2.3) records the total packet count at the last time a flow
	// was scored, so a flow with no new packets can be skipped. Cleared on eviction.
	lastScoredPkts = make(map[flowKey]uint64)
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

// persistAlert appends one alert per flow lifetime. dedupKey is the active
// flow key (used for suppression and cleared on eviction); logKey is the key
// written to the file, which for DDoS is the IP wildcard rather than the
// 5-tuple.
func persistAlert(dedupKey, logKey flowKey, attackName string) {
	if _, seen := alertedFlows[dedupKey]; seen {
		return
	}
	timestamp := time.Now().UTC().Format(time.RFC3339)
	line := fmt.Sprintf("%s,%s,%s", timestamp, attackName, canonicalKeyString(logKey))
	if err := appendUniqueLine(alertsPath, line); err != nil {
		log.Printf("Failed to persist alert: %v", err)
		return
	}
	alertedFlows[dedupKey] = struct{}{}
}

// persistSocReview logs cases where binary model detected malicious but multiclass model detected benign.
// These are high-confidence uncertain cases that warrant manual SOC team inspection.
func persistSocReview(k flowKey, binaryConf float64, multiclassClass int, multiclassConf float64) {
	if _, seen := socReviewedFlows[k]; seen {
		return
	}
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
		return
	}
	socReviewedFlows[k] = struct{}{}
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

			if isAllowlisted(fkey.IpA) || isAllowlisted(fkey.IpB) {
				log.Printf("[ALLOWLIST] refusing banlist entry targeting a trusted address: %s", canonicalKeyString(fkey))
				continue
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

// monitorBlocklist keeps the kernel threat-intel map in sync with a local file
// of known-bad IPs/CIDRs (one per line; '#' and ';' comments and trailing fields
// are tolerated, so raw feed formats like Spamhaus DROP work too). The file is
// refreshed out-of-band (see fetch_threat_intel.sh); this loop reconciles it into
// the map on a timer, adding new entries and removing ones that dropped out of the
// feed. The allowlist always overrides the blocklist in the datapath, so a feed
// false-positive on trusted infrastructure cannot cut connectivity.
func monitorBlocklist(filepath string, blockMap *ebpf.Map, interval time.Duration) {
	if blockMap == nil {
		return
	}

	known := make(map[lpmV4Key]struct{})
	val := uint32(1)

	sync := func() {
		file, err := os.Open(filepath)
		if err != nil {
			if !os.IsNotExist(err) {
				log.Printf("[BLOCKLIST] cannot open %s: %v", filepath, err)
			}
			return
		}
		defer file.Close()

		current := make(map[lpmV4Key]struct{})
		scanner := bufio.NewScanner(file)
		added, skipped := 0, 0
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) == 0 {
				continue
			}
			n, err := parseCIDROrIP(fields[0])
			if err != nil {
				skipped++
				continue
			}
			key, err := lpmKeyFromIPNet(n)
			if err != nil {
				skipped++
				continue
			}
			current[key] = struct{}{}
			if _, exists := known[key]; !exists {
				if err := blockMap.Put(&key, &val); err != nil {
					log.Printf("[BLOCKLIST] failed to program %s: %v", n.String(), err)
					continue
				}
				known[key] = struct{}{}
				added++
			}
		}
		if err := scanner.Err(); err != nil {
			log.Printf("[BLOCKLIST] error reading %s: %v", filepath, err)
		}

		removed := 0
		for key := range known {
			if _, present := current[key]; !present {
				if err := blockMap.Delete(&key); err != nil {
					log.Printf("[BLOCKLIST] failed to remove entry: %v", err)
					continue
				}
				delete(known, key)
				removed++
			}
		}
		if added > 0 || removed > 0 {
			log.Printf("[BLOCKLIST] synced %s: +%d -%d (total %d active, %d skipped)",
				filepath, added, removed, len(known), skipped)
		}
	}

	sync() // initial load before the first tick
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		sync()
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

// parseCIDROrIP accepts "1.2.3.4" or "1.2.3.0/24" and returns an IPv4 *net.IPNet.
func parseCIDROrIP(s string) (*net.IPNet, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			return nil, err
		}
		if n.IP.To4() == nil {
			return nil, fmt.Errorf("only IPv4 is supported: %s", s)
		}
		return n, nil
	}
	ip := net.ParseIP(s)
	if ip == nil || ip.To4() == nil {
		return nil, fmt.Errorf("invalid IPv4 address: %s", s)
	}
	return &net.IPNet{IP: ip.To4(), Mask: net.CIDRMask(32, 32)}, nil
}

// lpmKeyFromIPNet converts an IPv4 network into the eBPF LPM trie key. Addr
// carries the network-order address bytes: binary.LittleEndian.Uint32 over the
// 4-byte big-endian slice yields the raw value the kernel reads from the packet
// on this little-endian target (same convention as ipToUint32).
func lpmKeyFromIPNet(n *net.IPNet) (lpmV4Key, error) {
	ones, bits := n.Mask.Size()
	if bits != 32 {
		return lpmV4Key{}, fmt.Errorf("not an IPv4 mask")
	}
	ip4 := n.IP.To4()
	if ip4 == nil {
		return lpmV4Key{}, fmt.Errorf("not an IPv4 network")
	}
	return lpmV4Key{
		Prefixlen: uint32(ones),
		Addr:      binary.LittleEndian.Uint32(ip4),
	}, nil
}

// resolvConfNameservers returns the IPv4 nameservers listed in a resolv.conf.
func resolvConfNameservers(path string) []net.IP {
	var out []net.IP
	f, err := os.Open(path)
	if err != nil {
		return out
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) >= 2 && fields[0] == "nameserver" {
			if ip := net.ParseIP(fields[1]); ip != nil && ip.To4() != nil {
				out = append(out, ip.To4())
			}
		}
	}
	return out
}

// gatherSeedCIDRs auto-detects infrastructure that must never be scored or
// blocked: loopback, the router's own addresses on the attached interfaces, the
// default gateway(s), and the configured DNS resolvers. Note: the LAN subnet is
// deliberately NOT seeded - whitelisting it would skip scoring all client
// traffic, which is exactly what we want to protect.
func gatherSeedCIDRs(ifaces []string) []*net.IPNet {
	var nets []*net.IPNet
	add := func(n *net.IPNet, what string) {
		if n != nil {
			nets = append(nets, n)
			log.Printf("[ALLOWLIST] seed %s: %s", what, n.String())
		}
	}

	if _, n, err := net.ParseCIDR("127.0.0.0/8"); err == nil {
		add(n, "loopback")
	}

	for _, iface := range ifaces {
		link, err := netlink.LinkByName(iface)
		if err != nil {
			continue
		}
		addrs, err := netlink.AddrList(link, unix.AF_INET)
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if a.IP.To4() == nil {
				continue
			}
			add(&net.IPNet{IP: a.IP.To4(), Mask: net.CIDRMask(32, 32)}, "router-ip("+iface+")")
		}
	}

	if routes, err := netlink.RouteList(nil, unix.AF_INET); err == nil {
		for _, r := range routes {
			if r.Dst == nil && r.Gw != nil && r.Gw.To4() != nil {
				add(&net.IPNet{IP: r.Gw.To4(), Mask: net.CIDRMask(32, 32)}, "gateway")
			}
		}
	}

	for _, ns := range resolvConfNameservers("/etc/resolv.conf") {
		add(&net.IPNet{IP: ns, Mask: net.CIDRMask(32, 32)}, "dns")
	}

	return nets
}

// loadAllowlist programs the eBPF allowlist map from the auto-detected seeds plus
// the user file (whitelistPath), and keeps an in-memory copy for the userspace
// ban guard (isAllowlisted). Called once at startup before any goroutine reads
// allowlistNets.
func loadAllowlist(allowMap *ebpf.Map, ifaces []string) {
	nets := gatherSeedCIDRs(ifaces)

	if f, err := os.Open(whitelistPath); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			n, err := parseCIDROrIP(line)
			if err != nil {
				log.Printf("[ALLOWLIST] skipping invalid entry %q: %v", line, err)
				continue
			}
			nets = append(nets, n)
			log.Printf("[ALLOWLIST] seed file: %s", n.String())
		}
		f.Close()
	} else if !os.IsNotExist(err) {
		log.Printf("[ALLOWLIST] cannot read %s: %v", whitelistPath, err)
	}

	val := uint32(1)
	for _, n := range nets {
		key, err := lpmKeyFromIPNet(n)
		if err != nil {
			log.Printf("[ALLOWLIST] skipping %s: %v", n.String(), err)
			continue
		}
		if allowMap != nil {
			if err := allowMap.Put(&key, &val); err != nil {
				log.Printf("[ALLOWLIST] failed to program %s: %v", n.String(), err)
				continue
			}
		}
	}
	allowlistNets = nets
	log.Printf("[ALLOWLIST] %d trusted networks loaded", len(nets))
}

// isAllowlisted reports whether the raw (network-order) IPv4 address is covered
// by any trusted network. Userspace guard consulted before inserting a ban.
func isAllowlisted(ipRaw uint32) bool {
	ip := intToIP(ipRaw)
	for _, n := range allowlistNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// ifacesFlag is the comma-separated list of interfaces the sensor attaches to.
// Default is the LAN bridge alone: on a NAT router this is the only place where
// both directions of a routed flow carry the same (LAN-side) address. See
// attachInterface for why ingress on a second interface would not merge them.
var ifacesFlag = flag.String("ifaces", "br-lan",
	"comma-separated interfaces to attach to (ingress+egress on each)")

// minConfidence (2.1) is the Stage-2 confidence floor for ENFORCEMENT. Below it
// a malicious verdict is still alerted but not blocked. minPackets (2.2) is the
// maturity gate: a flow must have at least this many packets before it may be
// blocked, because the features of a very young flow are unreliable (Chapter 6.2).
var minConfidence = flag.Float64("min-confidence", 0.80,
	"minimum Stage-2 confidence required to enforce a block (below this: alert only)")

var minPackets = flag.Uint("min-packets", 8,
	"minimum total packets before a flow may be blocked (maturity gate)")

// blocklistRefresh (3.1) is how often the threat-intel file is re-synced into the
// kernel blocklist map. The file itself is refreshed out-of-band (cron + curl,
// see fetch_threat_intel.sh), keeping the agent free of any network dependency.
var blocklistRefresh = flag.Duration("blocklist-refresh", 10*time.Minute,
	"how often to re-sync the threat-intel blocklist file into the kernel")

// resolveIfaces returns the interface list to attach to. The DW_IFACES env var
// (comma separated) overrides the -ifaces flag so the agent can run unattended
// at boot without command-line editing.
func resolveIfaces(flagVal string) []string {
	val := flagVal
	if env := strings.TrimSpace(os.Getenv("DW_IFACES")); env != "" {
		val = env
	}
	var out []string
	for _, p := range strings.Split(val, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// attachInterface installs a clsact qdisc on ifaceName and attaches the eBPF
// program at BOTH the ingress and egress hooks. On a NAT router this is what
// lets one flow record capture both directions: tc ingress runs before netfilter,
// so the kernel has not yet translated addresses. On the LAN bridge the outbound
// half is seen at ingress (received from the LAN, before SNAT) and the inbound
// half is seen at egress (transmitted to the LAN, after reverse-NAT restored the
// LAN address). Both halves share the same canonical 5-tuple key and accumulate
// into a single flow_stats entry. Attaching ingress on a second interface (e.g.
// wan) would NOT merge them, because the WAN side only ever sees the translated
// router address - it would create a separate, still one-directional flow.
// It returns a cleanup func that detaches both filters and removes the qdisc.
func attachInterface(ifaceName string, progFD int) (func(), error) {
	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("find interface %q: %w", ifaceName, err)
	}

	// Create the clsact qdisc (equivalent to: tc qdisc add dev <iface> clsact).
	// clsact provides both the ingress and egress mini-qdiscs.
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	_ = netlink.QdiscAdd(qdisc) // ignore error if the qdisc already exists

	mkFilter := func(parent uint32, name string) *netlink.BpfFilter {
		return &netlink.BpfFilter{
			FilterAttrs: netlink.FilterAttrs{
				LinkIndex: link.Attrs().Index,
				Parent:    parent,
				Handle:    1, // handles are per-parent, so 1 is fine on both hooks
				Protocol:  unix.ETH_P_ALL,
			},
			Fd:           progFD,
			Name:         name,
			DirectAction: true,
		}
	}

	ingress := mkFilter(netlink.HANDLE_MIN_INGRESS, "dualwield_ingress")
	if err := netlink.FilterAdd(ingress); err != nil {
		return nil, fmt.Errorf("attach ingress filter on %q: %w", ifaceName, err)
	}
	egress := mkFilter(netlink.HANDLE_MIN_EGRESS, "dualwield_egress")
	if err := netlink.FilterAdd(egress); err != nil {
		_ = netlink.FilterDel(ingress)
		return nil, fmt.Errorf("attach egress filter on %q: %w", ifaceName, err)
	}

	cleanup := func() {
		if err := netlink.FilterDel(egress); err != nil {
			log.Printf("Warning: failed to remove egress filter on %s: %v", ifaceName, err)
		}
		if err := netlink.FilterDel(ingress); err != nil {
			log.Printf("Warning: failed to remove ingress filter on %s: %v", ifaceName, err)
		}
		if err := netlink.QdiscDel(qdisc); err != nil {
			log.Printf("Warning: failed to delete qdisc on %s: %v", ifaceName, err)
		}
	}
	return cleanup, nil
}

func main() {
	// Microsecond-resolution timestamps on every log line, used to measure
	// the attack-to-block latency in Chapter 6.5 (default log resolution is 1s).
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	flag.Parse()

	// DETECT_ONLY=1 observă și jurnalizează fluxurile, dar nu inserează nimic în
	// drop map și nu sincronizează banlist-ul. Folosit pentru măsurătoarea de
	// overhead din capitolul 6.4: traficul de test nu mai este blocat la mijloc.
	detectOnly := os.Getenv("DETECT_ONLY") != ""
	if detectOnly {
		log.Println("DETECT_ONLY active: detection and logging only, no blocking")
	}

	// 1. Load the compiled eBPF objects into the kernel
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("Failed to load eBPF objects: %v", err)
	}
	defer objs.Close()

	// 2. Attach the sensor to each configured interface (ingress + egress).
	ifaces := resolveIfaces(*ifacesFlag)
	if len(ifaces) == 0 {
		log.Fatalf("No interfaces to attach to (set -ifaces or DW_IFACES)")
	}

	var cleanups []func()
	for _, iface := range ifaces {
		cleanup, err := attachInterface(iface, objs.DualwieldEnforcer.FD())
		if err != nil {
			log.Printf("Warning: %v (skipping this interface)", err)
			continue
		}
		cleanups = append(cleanups, cleanup)
		log.Printf("Attached eBPF sensor to %s (ingress + egress)", iface)
	}
	if len(cleanups) == 0 {
		log.Fatalf("Failed to attach to any interface from %v", ifaces)
	}

	defer func() {
		log.Println("Cleaning up: detaching sensor and destroying qdiscs...")
		for _, c := range cleanups {
			c()
		}
		log.Println("Cleanup complete. Sensor detached and maps flushed.")
	}()

	// Load the allowlist before any traffic is scored. Trusted infrastructure
	// (router, gateway, DNS, loopback, plus user entries) is never blocked or
	// scored. Loaded regardless of DETECT_ONLY: the datapath check is always
	// active and we never want to alert on the gateway either.
	loadAllowlist(objs.AllowlistV4, ifaces)

	// 3. Start Banlist Monitor and setup polling for ML features

	if !detectOnly {
		go monitorBanlist(banlistPath, objs.DropFlowsMap, 5*time.Second)
		// Threat-intel reputation feed (3.1). Skipped in DETECT_ONLY so the
		// overhead measurement never drops traffic.
		go monitorBlocklist(threatIntelPath, objs.BlocklistV4, *blocklistRefresh)
	}
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
				activeCount := 0         // flows present in the table at this poll (Chapter 6.4 saturation)
				batchStart := time.Now() // poll-batch wall time (Chapter 6.5)
				var mlNanos int64        // cumulative pure ML inference time this batch

				for iterator.Next(&key, &stats) {
					activeCount++
					if !flowsFound {
						fmt.Println("--- NEW ML BATCH ---")
						flowsFound = true
					}

					// Eviction is evaluated on every poll; scoring is not.
					shouldEvict := false

					// 2.3: skip flows that received no new packets since the last
					// poll - re-running the model on an unchanged flow only re-derives
					// a verdict we already acted on. A flow still taking packets keeps
					// being re-scored (its count changes) until it matures.
					totalPkts := stats.PktsAToB + stats.PktsBToA
					prevPkts, seenBefore := lastScoredPkts[key]
					lastScoredPkts[key] = totalPkts
					changed := !seenBefore || prevPkts != totalPkts

					if changed {
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
						mlT0 := time.Now()
						binaryScores := binaryScore(features)
						mlNanos += time.Since(mlT0).Nanoseconds()
						binaryPrediction, binaryConfidence := predictAndConfidence(binaryScores)

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
							mlT1 := time.Now()
							multiclassScores := multiclassScore(features)
							mlNanos += time.Since(mlT1).Nanoseconds()
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
								log.Printf("[THREAT DETECTED] %s:%d -> %s:%d | Type: %s | Confidence: %.4f",
									intToIP(clientIP), ntohs(clientPort),
									intToIP(serverIP), ntohs(serverPort),
									attackName, multiclassConfidence)

								// Apply quarantine (5-tuple or IP wildcard block for DDoS)
								dummyValue := uint32(1)

								// If this is a DDoS class, insert port wildcards
								banKey := key
								if multiclassPrediction == 1 { // DDoS
									banKey.IpA = serverIP
									banKey.IpB = clientIP
									banKey.PortA = 0
									banKey.PortB = 0
								}

								// 2.1 + 2.2: the maturity gate and confidence floor gate
								// ENFORCEMENT only. Below either bar we still alert (detection
								// is preserved) but do not block, because Chapter 6.2 shows the
								// false positives came from immature/low-confidence verdicts.
								mature := totalPkts >= uint64(*minPackets)
								confident := multiclassConfidence >= *minConfidence

								switch {
								case isAllowlisted(banKey.IpA) || isAllowlisted(banKey.IpB):
									log.Printf("   -> [ALLOWLIST] refusing to quarantine flow touching a trusted address: %s", canonicalKeyString(banKey))
								case !mature:
									log.Printf("   -> [OBSERVING] %s: only %d pkts (< %d), not enforcing (alert only)",
										canonicalKeyString(banKey), totalPkts, *minPackets)
									persistAlert(key, banKey, attackName)
								case !confident:
									log.Printf("   -> [LOW-CONFIDENCE] %s: %.4f < %.2f, not enforcing (alert only)",
										canonicalKeyString(banKey), multiclassConfidence, *minConfidence)
									persistAlert(key, banKey, attackName)
								case detectOnly:
									persistAlert(key, banKey, attackName)
								default:
									if multiclassPrediction == 1 {
										log.Printf("   -> [QUARANTINE-IP] applying ports wildcard block: %s", canonicalKeyString(banKey))
									} else {
										log.Printf("   -> [QUARANTINE] applying flow block: %s", canonicalKeyString(banKey))
									}
									if err := objs.DropFlowsMap.Put(&banKey, &dummyValue); err != nil {
										log.Printf("   -> [ERROR] Failed to push quarantine to kernel: %v", err)
									} else {
										if _, auto := autoBanClasses[multiclassPrediction]; auto {
											persistBanlistEntry(banKey)
										}
										persistAlert(key, banKey, attackName)
									}
								}
							}
						}
					} // end if changed (2.3 skip re-scoring unchanged flows)

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
					log.Printf("[TIMING] batch=%v ml_total=%.2fms flows=%d (Chapter 6.5)",
						time.Since(batchStart), float64(mlNanos)/1e6, activeCount)
				}

				if len(flowsToEvict) > 0 {
					for _, k := range flowsToEvict {
						if err := objs.ActiveFlows.Delete(&k); err != nil {
							log.Printf("[HOUSEKEEPING] Failed to delete flow %s: %v", canonicalKeyString(k), err)
						}
						// Allow a future flow with the same 5-tuple to alert again.
						delete(alertedFlows, k)
						delete(socReviewedFlows, k)
						delete(lastScoredPkts, k)
					}
					log.Printf("[HOUSEKEEPING] Evicted %d closed/stale flows from kernel memory", len(flowsToEvict))
				}
			}
		}
	}()

	<-stopper
	log.Println("Detaching firewall and exiting...")
}
