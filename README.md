# Dataplane Router

## Purpose
    The provided code is a C implementation of the dataplane component of a router.
It handles forwarding packets between different interfaces (different computers or
another router).

## Dependencies
- 'queue.h': Simple implementation of a queue
- 'lib.h': Different utility functions
- 'protocols.h': Contains the definitions of different protocols
- 'string.h': Standard C library for string manipulation
- 'netinet/in.h' & 'arpa/inet.h': Used for handling internet addresses and protocols

## Structures
1. 'struct packet': a network packet that has a buffer (payload), size and interface
    information
2. 'struct arp_table_entry': entry in the ARP table
3. 'struct route_table_entry': entry in the routing table
4. 'struct iphdr' & 'struct icmphdr' & 'struct ether_header' & 'struct arp_header' for
    headers of different protocols

## Functions
1. 'create_packet': creates a new network packet via buf,len and interface
2. 'get_arp_entry': retrieves an ARP entry based on the provided IP address
3. 'get_best_route_bs': performs a binary search in order to find the best route 
    interface for the given destination IP address
4. 'swap_mac_addresses': swaps the source and destination addresses in the given Ethernet
    header
5. 'send_icmp': sends an icmp packet
6. 'send_arp': sends an arp request or reply packet
7. 'forwarding': forwards a packet based on the best route entry in the routing table
8. 'comparator': used to sort the the routing table based on the prefix and mask
    (needed for the binary search)
9. main

## Execution
    Initialize the router with the command-line arguments and allocates memory for the arp
table and route table. Then it reads the route table using rtable and sorts the routing
table. Proceds with an infinite loop in order to handle incoming packets. Receives packets
from any link (any network interface) and parses the ether header of the packet so the router
knows how to branch its handling process.
    If the received packet is an IP packet, the program performs forwarding based on the
routing table. Calculates the new checksum and verifies if it the same as the previous one.
Then calculates the best route (that the packet should be sent on) and the TTL. Verifies if
there isn't an arp entry in the arp table, proceeds to calculate the MAC address of the next
hop using an ARP request. If all is good, then it forwards the IP packet to the appropiate
outgoing interface.
    If the received packet is an ARP packet, the router extracts the arp header and checks the
type (if it is a request or a reply). For the request process, checks if the ip target address
matches any of its interfaces and there on extracts the packet containing its own MAC address
and sends it back to the requester. For the reply process, the router updates the arp table
and checks if ARP reply packet contains information for an IP address that the router previously
enqueued packets due to an ARP cache miss. The router dequeues the packets and proceeds with the
forwarding process.
    If the received packet is an ICMP packet, the router parses the ICMP header to determine the
type of ICMP message. For Echo Request, the router will construct an ICMP Echo Reply packet, with
the same payload and size as the original packet, only that the destination IP and MAC addresses
are swapped. For an ICMP Erorr Message, the router will construct a packet to inform the sender
about the issue encountered.


On the local checker I got 91 points.