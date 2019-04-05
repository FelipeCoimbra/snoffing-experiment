
#include "spoofing.h"
#include "packet.h"

#include <sys/socket.h>
#include <netinet/ip.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/*
    Send raw built ip packet through the socket
*/
void send_raw_ip_packet(int sock_desc, struct ippacket_header_t* ip_header) {
    
    //
    //  Setup destination
    //
    struct sockaddr_in dest_info;
    dest_info.sin_family = AF_INET;
    dest_info.sin_addr = ip_header->iph_destip;

    //
    //  Send raw packet
    //
    sendto(sock_desc,                       // Socket to send packet
            ip_header,                      // Content: Built ip packet
            ntohs(ip_header->iph_len),      // Total length of ip packet
            0,                              // Flags
            (struct sockaddr *)&dest_info,  // Destination information
            sizeof(dest_info));             // Destination information length
}


/*
    Builds ICMP/IP Packet destined to a given IP address and with a certain content into ip_header
*/
void build_icmp(struct ippacket_header_t* ip_header, const char* dest_ip, const char* content) {
    // TODO
}

/*
    Builds UDP/IP Packet destined to a given IP address and with a certain content into ip_header
*/
void build_udp(struct ippacket_header_t* ip_header, const char* dest_ip, const char* content) {
    // TODO
}

/*
    Returns appropriate packet builder function for the given protocol or NULL if there's no packet builder for the 
    required protocol.
*/
void (*get_ippacket_builder(const char* protocol))(struct ippacket_header_t*, const char*, const char*) {
    if (strcmp(protocol, "icmp") == 0) {
        return build_icmp;
    }
    if (strcmp(protocol, "udp") == 0) {
        return build_udp;
    }

    printf("Error: Invalid protocol");
    exit(-1);
}

// - Construct the IP header 
// - Construct the TCP/UDP/ICMP header ...
// - Fill in the data part if needed ...
// Note: you should pay attention to the network/host byte order.

void spoof(int sock_desc, const char* dest_ip, const char* protocol, const char* content) {
    //
    // Retrieve appropriate packet builder
    //
    void (*packet_builder)(struct ippacket_header_t*, const char*, const char*) = get_ippacket_builder(protocol);

    //
    // Build packet
    //
    struct ippacket_header_t* ip_header;
    (*packet_builder)(ip_header, dest_ip, content);

    //
    // Send built packet
    //
    send_raw_ip_packet(sock_desc, ip_header);
}