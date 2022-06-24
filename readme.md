# Network services scanner

Simple TCP, UDP network scanner. The program scans the selected ports on the given network device defined by the IP address and prints the state of the ports *(open, filtered, closed)* on the standard output. Packets are send using BSD sockets and response capture is implemented using the libpcap library.

- Super user rights are required to run the program.
- Only IPv4 network protocol is supported.
- Scan only computers in your possession.

**TCP scanning**  
It only sends SYN packets, so it does not perform a complete 3-way handshake. If an RST response arrives - the port is marked as closed. If no response is received from the scanned port for a some time interval, the port is verified with another packet and only then port is marked as filtered. If a service is running on that port, the port is marked as open. See RFC 793 for more.

**UDP scanning**  
For UDP scanning, it is assumed that the computer responds with an ICMP message of type 3, code 3 (port unreachable) when the port is closed. Other ports are considered as open.

## Installation
```
./scan {-i <interface>} -pu <port-ranges> -pt <port-ranges> [<domain-name> | <IP-address>]
```

where:  
- -i \<interface\> - argument is the interface identifier. This parameter is optional, in its absence, the first IEEE 802 interface that has a non-loopback IP address assigned is selected.  
- -pt, pu \<port-ranges\> - scanned ports by TCP/UDP (eg. -pt 22 or -pu 1-65535 or -pt 22,23,24)
- \<domain-name\> | \<ip-address\> - domain name or IP address of scanned computer  

## Example
```
sudo ./scan -pt 21,22,143 -pu 53,67 localhost
```

> Interesting ports on localhost (127.0.0.1):  
> PORT     STATE  
> 21/tcp	 closed  
> 22/tcp 	 open  
> 143/tcp	 filtered  
> 53/udp	 closed  
> 67/udp	 open  
