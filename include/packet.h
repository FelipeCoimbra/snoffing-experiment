#ifndef __PACKET_H__
#define __PACKET_H__

#include <arpa/inet.h>

typedef unsigned char u_char;
typedef unsigned short int u_short;

/*
    Basic header for ethernet frames according to IEEE 802.3 standard
    https://en.wikipedia.org/wiki/Ethernet_frame
    
    Destination MAC: 6 bytes
    Source MAC: 6 bytes
    Packet Type: 2 bytes
    Total: 14 bytes
*/
#define MAC_ADDR_LEN 6

struct ethframe_header_t {
    u_char ether_dhost[MAC_ADDR_LEN];   // Destination MAC Address
    u_char ether_shost[MAC_ADDR_LEN];   // Source MAC Address
    u_short ether_type;                 // Packet Type
};

/*
    IP packet header structure
    https://en.wikipedia.org/wiki/IPv4#Packet_structure
*/
#define IP_PACKET_T 0x800

struct ippacket_header_t {
    u_char          iph_ihl:4,      // IP header length (4 bits)
                    iph_ver:4,      // IP version (4 bits)
                    iph_tos;        // Type of service
    u_short         iph_len,        // IP Packet length (data + header)
                    iph_ident,      // Identification
                    iph_flag:3,     // Fragmentation flags
                    iph_offset:13;  // Flags offset
    u_char          iph_ttl,        // Time to Live
                    iph_protocol;   // Protocol type
    u_short         iph_chksum;     // IP datagram checksum
    struct in_addr  iph_source,     // Source IP Address
                    iph_dest;       // Destination IP address
};

#endif
