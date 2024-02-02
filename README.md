# Pure Go tcpdump clone

Useful if you need a truly statically linked tcpdump-like tool for Linux. For example, this will run on Container-Optimized OS on GKE (Google Kubernetes Engine).

Install:
```bash
CGO_ENABLED=0 GOOS=linux go install github.com/iangudger/tcpdump
```

Run:
```bash
$ $(go env GOPATH)/bin/tcpdump -h
~/go/bin/tcpdump [flags]
  -h	Print usage.
  -help
    	Print usage.
  -i string
    	Interface to read packets from. (default "lo")
  -len uint
    	Max packet length. (default 65536)
  -out string
    	Path to output file in pcap format. (Default is a randomly generated directory in /tmp)
$ sudo $(go env GOPATH)/bin/tcpdump
2024/02/02 08:07:01 Saving capture to: /tmp/2287002912/dump.pcap
2024/02/02 08:07:01 Capturing interface #1 (lo)
```
