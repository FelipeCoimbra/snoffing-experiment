
#include "sniffing.h"
#include "packet.h"

#include <time.h>
#include <stdio.h>
#include <string.h>

#define TIMELABEL_MAX_SIZE 16
#define PROTOLABEL_MAX_SIZE 32

void get_time_label(char *buffer) {
    time_t raw_time;
    struct tm* current_time;

    // Fill current time and convert to local time zone
    time(&raw_time);
    current_time = localtime(&raw_time);

    char label[TIMELABEL_MAX_SIZE];
    sprintf(label, "[%d:%d:%d]", current_time->tm_hour, current_time->tm_min, current_time->tm_sec);
    strncpy(buffer, label, TIMELABEL_MAX_SIZE);
}

void get_protocol_label(char *buffer, u_char protocol) {
    char label[PROTOLABEL_MAX_SIZE] = "Protocol: ";

    switch (protocol)
    {
        case IPPROTO_TCP:
            strcat(label, "TCP");
            break;

        case IPPROTO_UDP:
            strcat(label, "UDP");
            break;
        
        case IPPROTO_ICMP:
            strcat(label, "ICMP");
            break;

        default:
            strcat(label, "others");
            break;
    }

    strncpy(buffer, label, PROTOLABEL_MAX_SIZE);
}

/* 
    This simple callback only alerts upon receipt and register the receipt time
*/
void simple_callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    char current_time[TIMELABEL_MAX_SIZE];
    get_time_label(current_time);

    // Print message
    printf("%s Got a packet!\n", current_time);
}

/* 
    This callback prints the time label, protocol type, source ip address and destination ip address
        of every IP packet received
*/
void print_proto_src_dst(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    char current_time[TIMELABEL_MAX_SIZE];
    get_time_label(current_time);

    struct ethframe_header_t* eth_header = (struct ethframe_header_t*)packet;

    // Convert from network convention to host convention and compare
    if (ntohs(eth_header->ether_type) == IP_PACKET_T) {
        // Get IP packet header
        struct ippacket_header_t* ip_header = (struct ippacket_header_t*)(packet + sizeof(struct ethframe_header_t));

        char data_protocol[PROTOLABEL_MAX_SIZE];
        get_protocol_label(data_protocol, ip_header->iph_protocol);

        // Print message
        printf("%s %s \n"
                "\tSource addr: %s\n"
                "\tDestination addr: %s\n", 
                current_time, data_protocol,
                inet_ntoa(ip_header->iph_sourceip),
                inet_ntoa(ip_header->iph_destip));
    } else {
        // Just call simple_callback
        simple_callback(args, header, packet);
    }
}