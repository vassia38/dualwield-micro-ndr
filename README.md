meant to run on openwrt23.05.3/ramips,
see https://openwrt.org/docs/guide-developer

# Dualwield - a micro Network Detection & Resposne


## Prerequisites

### environment
clang llvm gcc libbpf libbpf-devel libxdp libxdp-devel xdp-tools bpftool kernel-headers

### Router packages
bpftool xdp-filter xdp-loader xdpdump libxdp libbpf

### Check OpenWRT can run XDP

Check Kernel Version: <br/>
`uname -r`
> should be > 4.8

Check JIT Status: XDP performance relies heavily on the Just-In-Time compiler.<br/>
`sysctl net.core.bpf_jit_enable`
> Value should be 1 or 2. If it's 0, try `sysctl -w net.core.bpf_jit_enable=1`.

Verify BPF Filesystem: <br/>
`mount | grep bpf`
> If empty, run: `mount -t bpf bpffs /sys/fs/bpf`.

Feature probing: <br/>
`bpftool feature probe | grep xdp`
> Should see something like `eBPF program_type xdp is available`

Identify interfaces and drivers. List device names for WAN and LAN with `ip link`. Then read `ethtool -i` to see the driver. That predicts whether native mode will attach or fall back to generic mode.


## Sources:
[https://phb-crystal-ball.org/set-up-xdp-firewall-in-openwrt/#When_it_makes_sense_on_home_lab_and_edge_routers](https://phb-crystal-ball.org/set-up-xdp-firewall-in-openwrt/#When_it_makes_sense_on_home_lab_and_edge_routers)
[https://www.tigera.io/learn/guides/ebpf/ebpf-xdp/](https://www.tigera.io/learn/guides/ebpf/ebpf-xdp/)
[https://www.gargoyle-router.com/old-openwrt-coding.html](https://www.gargoyle-router.com/old-openwrt-coding.html)
