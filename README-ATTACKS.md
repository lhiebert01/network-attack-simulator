Port Scan Attack Explanation
What is a Port Scan?
A port scan is a technique used to identify open ports and services on a network host. Attackers use port scanning to discover services they can exploit.

How it Works
The attacker sends packets to a range of port addresses on a host, analyzing which ports respond and how. Common types include:

SYN Scan: Sends SYN packets as if initiating a connection but never completes the handshake
TCP Connect: Completes the full TCP handshake
UDP Scan: Sends UDP packets to identify UDP services
Detection Method
Port scans are detected by monitoring for:

Multiple connection attempts from a single source to different ports in a short time period
Connection attempts to closed or unusual ports
Incomplete TCP handshakes (in the case of SYN scans)
Log File Format
Example log entry:

# Fields: ts uid id.orig_h id.resp_p proto scan_attempts anomaly_type severity

                            1741500372.67890 XdJhQW7Q9T 192.168.1.50 80 tcp 15 Port_Scanning Medium
ts
Timestamp in UNIX epoch format
 
uid
Unique identifier for the connection
 
id.orig_h
Source IP address (the scanner)
 
id.resp_p
Destination port
 
proto
Protocol used (tcp, udp)
 
scan_attempts
Number of scan attempts detected
 
anomaly_type
Type of anomaly detected
 
severity
Severity level of the detected anomaly


Denial of Service (DoS) Attack Explanation
What is a DoS Attack?
A Denial of Service attack aims to make a service unavailable by overwhelming it with traffic or exploiting vulnerabilities that cause the service to crash or become unresponsive.

How it Works
Common DoS techniques include:

SYN Flood: Sending many SYN packets without completing handshakes, exhausting connection resources
UDP Flood: Overwhelming a target with UDP packets
HTTP Flood: Sending a high volume of HTTP requests to overwhelm a web server
Detection Method
DoS attacks are detected by monitoring for:

Unusual spikes in traffic volume
High number of connections from a single source
Abnormal ratios of specific packet types (e.g., many SYN packets without ACKs)
Resource exhaustion indicators (high CPU, memory usage, etc.)
Log File Format
Example log entry:

# Fields: ts uid id.orig_h id.resp_h id.resp_p proto service packets_count anomaly_type severity

                            1741500372.89012 CjhRZG3Tsa 192.168.1.100 192.168.1.10 80 tcp http 10000 SYN_Flood High
ts
Timestamp in UNIX epoch format
 
uid
Unique identifier for the connection
 
id.orig_h
Source IP address (attacker)
 
id.resp_h
Destination IP address (target)
 
id.resp_p
Destination port
 
proto
Protocol used
 
service
Service being targeted
 
packets_count
Number of packets detected in the attack
 
anomaly_type
Type of DoS attack detected
 
severity
Severity level of the detected anomaly


Brute Force Attack Explanation
What is a Brute Force Attack?
A brute force attack attempts to gain unauthorized access to systems by systematically trying all possible combinations of passwords or encryption keys until the correct one is found.

How it Works
The attacker repeatedly attempts to log in to a service (like SSH, FTP, or a web application) using different password combinations. This can be done using:

Dictionary Attacks: Using a list of common words and passwords
Pure Brute Force: Trying every possible combination of characters
Credential Stuffing: Using leaked username/password pairs from other breaches
Detection Method
Brute force attacks are detected by monitoring for:

Multiple failed login attempts from the same source
Login attempts occurring at unusual speeds (faster than human typing)
Login attempts outside of normal hours or from unusual locations
Sequential or patterned login attempts
Log File Format
Example log entry:

# Fields: ts uid id.orig_h id.resp_h id.resp_p proto service login_attempts user anomaly_type severity

                            1741500373.12345 Hj3bNm7Kl0 192.168.1.75 192.168.1.20 22 tcp ssh 5 admin Brute_Force_SSH High
ts
Timestamp in UNIX epoch format
 
uid
Unique identifier for the connection
 
id.orig_h
Source IP address (attacker)
 
id.resp_h
Destination IP address (target)
 
id.resp_p
Destination port
 
proto
Protocol used
 
service
Service being targeted (ssh, ftp, etc.)
 
login_attempts
Number of login attempts detected
 
user
Username being targeted
 
anomaly_type
Type of brute force attack detected
 
severity
Severity level of the detected anomaly

Data Exfiltration Attack Explanation
What is Data Exfiltration?
Data exfiltration is the unauthorized transfer of sensitive data from a system. It's often the final stage of an attack after an attacker has gained access and located valuable data.

How it Works
Attackers use various techniques to extract data, including:

DNS Tunneling: Hiding data in DNS queries
ICMP Tunneling: Embedding data in ICMP packets
Encrypted Channels: Using encrypted connections to hide data transfer
Steganography: Hiding data within other files or protocols
Detection Method
Data exfiltration is detected by monitoring for:

Unusual outbound traffic patterns or volumes
Large file transfers to external destinations
Unexpected protocol usage (e.g., DNS with unusually large payloads)
Communications with known malicious domains or unusual destinations
Data transfers occurring at unusual times
Log File Format
Example log entry:

# Fields: ts uid id.orig_h id.resp_h id.resp_p proto service data_size anomaly_type severity

                            1741500374.56789 Pq5rSt8Uv1 192.168.1.60 8.8.8.8 53 udp dns 1000 DNS_Exfiltration High
ts
Timestamp in UNIX epoch format
 
uid
Unique identifier for the connection
 
id.orig_h
Source IP address (internal compromised host)
 
id.resp_h
Destination IP address (external server)
 
id.resp_p
Destination port
 
proto
Protocol used
 
service
Service being used for exfiltration
 
data_size
Size of data being exfiltrated (in bytes)
 
anomaly_type
Type of exfiltration detected
 
severity
Severity level of the detected anomaly

