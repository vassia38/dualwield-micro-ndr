meant to run on openwrt23.05.3/ramips,
see https://openwrt.org/docs/guide-developer

# Dualwield - a micro Network Detection & Resposne


## Prerequisites

### environment
clang llvm gcc libbpf libbpf-devel libxdp libxdp-devel xdp-tools bpftool kernel-headers

### Router packages
bpftool xdp-filter xdp-loader xdpdump libxdp libbpf

### Check OpenWRT can run XDP

Check Kernel Version:
`uname -r`
> should be > 4.8

Check JIT Status: XDP performance relies heavily on the Just-In-Time compiler.
`sysctl net.core.bpf_jit_enable`
> Value should be 1 or 2. If it's 0, try `sysctl -w net.core.bpf_jit_enable=1`.

Verify BPF Filesystem:
`mount | grep bpf`
> If empty, run: mount -t bpf bpffs /sys/fs/bpf.

Feature probing:
bpftool feature probe | grep xdp
> Should see something like "eBPF program_type xdp is available"
