#ifndef __SNIFFING_H__
#define __SNIFFING_H__

#include <pcap.h>

typedef unsigned char u_char;

void simple_callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void print_proto_src_dst(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void steal_callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

#endif