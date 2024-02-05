## gait: Zeek Extension to Collect Metadata for Profiling of Endpoints and Proxies ##

gait is a collection of zeek scripts that adds metadata to conn, ssl, and ssh logs. This metadata supports profiling of endpoints and proxies. A core use case of gait is to counter malicious web clients that use deceptive infrastructure.

gait collects two major types of metadata:

 * Attributes such as default TCP options which helps identify the software used by endpoints and intermediaries
 * Timing data such as TCP, TLS, and SSH inferred round trip times (RTT) which helps understand path taken by traffic

### Relationship to Other Software ###
 
 * zeek: gait is a zeek extension
 * p0f (and other network stack fingerprinting tools): gait collects the raw metadata needed for network stack fingerprinting for all connections, but currently does not implement heuristics or a database to label given fingerprints
 * ja3: gait is designed to complement ja3, adding:
    * Timing analysis such as TLS RTT and TLS Hello delay

gait does not address collection of HTTP or other application layer metadata as widespread encryption makes observation of this data by passive sensors infeasible in most situations.

### Example Analytics using gait Metadata ###

The metadata collected with gait can be used to identify use of various types of intermediaries for web traffic. For example, the following proxy types can be profiled using the specified attributes and timing metadata.

 * Layer 3 (VPN)
   * Attributes: Lower than default MSS
   * Timing: Higher than expected TCP RTT
 * Layer 4 (SOCKS, Tor)
   * Attributes: Potential mismatch between network stack fingerprint (OS of exit node) and TLS/HTTP fingerprints (Browser)
   * Timing: Normal TCP RTT, higher than expected TLS RTT
 * Layer 7 (HTTP Proxy, AitM frameworks)
   * Attributes: Potential mismatch between network stack/TLS fingerprints (OS of proxy, proxy software) and HTTP fingerprint (Browser)
   * Timing: Normal TCP and TLS RTT, higher than expected HTTP RTT

See included presentation for examples of use.
  
### License ###

gait is licensed under BSD 3-clause, same as zeek.

### Install ###

gait can be installed with zkg.

```zkg install gait```
