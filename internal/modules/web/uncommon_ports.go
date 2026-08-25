// uncommon_ports.go — the uncommon web-port list for the httpx probe.
//
// v1 probes 80, 443 AND this list in a single httpx pass
// (reconftw.cfg:179-180 WEBPROBE_PORTS="80,443,${UNCOMMON_PORTS_WEB}",
// modules/web.sh:139). v2 declared the whole configuration surface for it —
// web.probe.uncommon_enabled (DEFAULT TRUE), uncommon_threads, uncommon_timeout,
// plus legacy aliases telling a migrating operator that HTTPX_UNCOMMONPORTS_*
// had been carried over — and then used NONE of those fields anywhere in the
// module code. The capability was configuration-only.
//
// The cost of that gap, measured: on hackerone.com, a.ns and b.ns serve HTTP on
// 2096 and 8443. v1 found them, v2 did not, and they were the ENTIRE remaining
// live-host parity gap (10 of 12 hosts, 16 percent removed against a 10 percent
// tolerance).
//
// SINGLE SOURCE OF TRUTH: this mirrors config/uncommon_ports_web.txt, which v1
// reads at runtime. It is a Go constant rather than an embed because //go:embed
// cannot reference a path outside its own package directory, and copying the
// file in would create the same two-files-that-must-stay-in-sync trap this repo
// already has elsewhere. TestUncommonPortsMatchV1Config reads the v1 file and
// fails on any drift.

package web

const uncommonWebPorts = "81,300,591,593,832,981,1010,1311,1099,2082,2095,2096,2480,3000,3001,3002,3003,3128,3333,4243,4567,4711,4712,4993,5000,5104,5108,5280,5281,5601,5800,6543,7000,7001,7396,7474,8000,8001,8008,8014,8042,8060,8069,8080,8081,8083,8088,8090,8091,8095,8118,8123,8172,8181,8222,8243,8280,8281,8333,8337,8443,8500,8834,8880,8888,8983,9000,9001,9043,9060,9080,9090,9091,9092,9200,9443,9502,9800,9981,10000,10250,11371,12443,15672,16080,17778,18091,18092,20720,32000,55440,55672"
