## warning ##
Watchout what you do with this - you'll probably lose connection until you restart the router

`<br/>
\# 1. Load the program from the file and 'pin' it to the BPF filesystem <br/>
\# This keeps the program loaded in memory even if bpftool exits. <br/>
bpftool prog load /tmp/dumbdropper.o /sys/fs/bpf/dumbdropper <br/>
\# 2. Attach the program to the interface (e.g., br-lan) <br/>
\# We use 'xdpgeneric' to ensure compatibility. <br/>
bpftool net attach xdpgeneric pinned /sys/fs/bpf/dumbdropper dev br-lan
`


find output object in <br/>
`build_dir/target-mipsel_24kc_musl/dumbdropper/.pkgdir/dumbdropper/bin/dumbdropper.o`
