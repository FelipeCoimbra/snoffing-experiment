
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
    Calculates the checksum of a given buffer
*/
u_short in_cksum(u_short *buf, int length) {
    u_short *w = buf;
    int nleft = length;

    int sum = 0;
    u_short aux = 0;

    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1) {
        *(u_char *)(&aux) = *(u_char *)w;
        sum += aux;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (u_short)(~sum);
}

void build_ip(struct ippacket_header_t* ip, const char* dest_ip) {
    ip->iph_iver = 4;
    ip->iph_ihl = 5;
    ip->iph_ttl = 20;
    ip->iph_sourceip.s_addr = inet_addr("161.24.4.60"); // Fake IP
    ip->iph_destip.s_addr = inet_addr(dest_ip);
    ip->iph_protocol = IPPROTO_ICMP;
    ip->iph_len = htons(sizeof(struct ippacket_header_t) + sizeof(struct icmppacket_header_t));
}

#define ICMP_PACKET_LENGTH 1500
#define ICMP_REQUEST_T 8
#define ICMP_REPLY_T 0

/*
    Builds ICMP/IP Packet destined to a given IP address and with a certain content into ip_header
*/
void build_icmp(struct ippacket_header_t** ip_header, const char* dest_ip, const char* content) {
    //
    //  Step 1a - Fill dynamically allocated buffer with ICMP header
    //
    *ip_header = (struct ippacket_header_t*)malloc(ICMP_PACKET_LENGTH * sizeof(char));
    memset(*ip_header, 0, ICMP_PACKET_LENGTH);

    struct icmppacket_header_t* icmp = (struct icmppacket_header_t*)
                                        (*ip_header + sizeof(struct icmppacket_header_t));
    // Set as request
    icmp->icmph_type = ICMP_REQUEST_T;

    // Calculate integrity checksum
    icmp->icmph_chksum = in_cksum((u_short *)icmp, sizeof(struct icmppacket_header_t));

    //
    //  Step 1b - Fill the IP header
    //
    build_ip((struct ippacket_header_t*)*ip_header, dest_ip);
}

/*
    Builds UDP/IP Packet destined to a given IP address and with a certain content into ip_header
*/
void build_udp(struct ippacket_header_t** ip_header, const char* dest_ip, const char* content) {
    // TODO
    *ip_header = NULL;
}

/*
    Returns appropriate packet builder function for the given protocol or NULL if there's no packet builder for the 
    required protocol.
*/
void (*get_ippacket_builder(const char* protocol))(struct ippacket_header_t**, const char*, const char*) {
    if (strcmp(protocol, "icmp") == 0) {
        return build_icmp;
    }
    if (strcmp(protocol, "udp") == 0) {
        return build_udp;
    }

    return NULL;
}

// - Construct the IP header 
// - Construct the TCP/UDP/ICMP header ...
// - Fill in the data part if needed ...
// Note: you should pay attention to the network/host byte order.

void spoof(int sock_desc, const char* dest_ip, const char* protocol, const char* content) {
    //
    // Retrieve appropriate packet builder
    //
    void (*packet_builder)(struct ippacket_header_t**, const char*, const char*) = get_ippacket_builder(protocol);

    if (packet_builder == NULL) {
        printf("Error: Invalid protocol %s", protocol);
        exit(-1);
    }

    //
    // Step 1 - Build packet
    //
    struct ippacket_header_t* ip_header;
    (*packet_builder)(&ip_header, dest_ip, content);

    if (ip_header == NULL) {
        printf("Error while building packet for protocol %s\n", protocol);
        exit(-1);
    }

    //
    // Step 2 - Send built packet
    //
    send_raw_ip_packet(sock_desc, ip_header);
    // free(ip_header);
}