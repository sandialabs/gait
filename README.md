## Download: Gait is now officially apart of zkg!  ##
https://github.com/zeek/packages/tree/master/sandialabs
Make sure you have an updated version of zkg and you should be able to pull directly from zeek's package manager. 

## gait: Zeek Extension to Collect Metadata for Profiling of Endpoints and Proxies ##

gait is a collection of zeek scripts that adds metadata to conn and ssl logs. This metadata supports profiling of endpoints and proxies. A core use case of gait is to counter malicious web clients that use deceptive infrastructure.

gait collects two major types of metadata:

 * Attributes such as default TCP options which helps identify the software used by endpoints and intermediaries
 * Timing data such as TCP TLS SSH layer inferred round trip times (RTT) which helps understand path taken by traffic

### Relationship to Other Software ###
 * zeek: gait is a zeek extension
 * p0f (and other network stack fingerprinting tools): gait collects the raw metadata needed for network stack fingerprinting for all connections, but currently does not implement heuristics or a database to label given fingerprints
 * ja3: gait is designed to complement ja3, adding:
    * Some TLS attributes not covered by ja3
    * Timing analysis such as TLS RTT and delay between TCP handshake and Client Hello

gait does not address collection of HTTP or other application layer metadata as widespread encryption makes observation of this data by passive sensors infeasible in most situations.

### Example Analytics using gait Metadata ###

The metadata collected with gait can be used to identify use of various types of intermediaries for web traffic. For example, the following client proxy types can be profiled using the specified attributes and timing metadata.

 * Layer 3 (VPN)
   * Attributes: Lower than default MSS
   * Timing: Higher than expected TCP RTT
 * Layer 4 (SOCKS, tOR)
   * Attributes: Potential mismatch between network stack fingerprint (OS of exit node) and TLS/HTTP fingerprints (Browser)
   * Timing: Normal TCP RTT, higher than expected TLS RTT
 * Layer 7 (HTTP Proxy, SSH)
   * Attributes: Potential mismatch between network stack fingerprint (OS of proxy) and HTTP fingerprints (Browser)
   * Timing: Higher than expected HTTP redirect/resource latency
   * SSH Timing: High than expected latency compared to tcp and authentication duration. 

### License ###

gait is licensed under BSD 3-clause, same as zeek

