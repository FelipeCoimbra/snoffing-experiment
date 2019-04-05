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
    u_char          iph_iver:4,      // IP header length (4 bits)
                    iph_ihl:4,      // IP version (4 bits)
                    iph_tos;        // Type of service
    u_short         iph_len,        // IP Packet length (data + header)
                    iph_ident,      // Identification
                    iph_flag:3,     // Fragmentation flags
                    iph_offset:13;  // Flags offset
    u_char          iph_ttl,        // Time to Live
                    iph_protocol;   // Protocol type
    u_short         iph_chksum;     // IP datagram checksum
    struct in_addr  iph_sourceip,   // Source IP Address
                    iph_destip;     // Destination IP address
};

/*
    TCP packet header structure
    https://en.wikipedia.org/wiki/Transmission_Control_Protocol#TCP_segment_structure
*/
typedef uint32_t tcp_seq;

struct tcppacket_header_t {
        u_short th_sport;               // Source port 
        u_short th_dport;               // Destination port 
        tcp_seq th_seq;                 // Sequence number 
        tcp_seq th_ack;                 // Acknowledgement number 
        u_char  th_off:4,               // Data offset, rsvd 
                th_reserved:3;          // Reserved area
        u_short th_flags:9;             // Flags
        u_short th_win;                 // Window 
        u_short th_sum;                 // Checksum 
        u_short th_urp;                 // Urgent pointer 
};


#endif
