#include "sniffing.h"

#include <stdlib.h>

void print_usage() {
    printf("Usage: sniffing <NETWORK INTERFACE>\n");
}

/*
    Args:
        1 - Network Interface identifier
*/
int main(int argc, char* argv[]) {

    if (argc < 2) {
        print_usage();
        exit(1);
    }

    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    
    //
    //  Network interface identification
    //
    const char* NETWORK_INTERFACE = argv[1];

    //
    //  BPF Filter Setup
    //
    char filter_exp[] = "ip proto icmp";
    bpf_u_int32 net;

    // Step 1: Open live pcap session on NIC with name NETWORK_INTERFACE
    handle = pcap_open_live("wlp3s0", BUFSIZ, 1, 1000, errbuf);

    // Step 2: Compile filter_exp into BPF psuedo-code
    // pcap_compile(handle, &fp, filter_exp, 0, net);
    // pcap_setfilter(handle, &fp);
    
    // Step 3: Capture packets
    pcap_loop(handle, -1, simple_callback, NULL);

    //Close the handle
    pcap_close(handle);
    
    return 0;
}
    // Note: don’t forget to add "-lpcap" to the compilation command.
    // For example: gcc -o sniff sniff.c -lpcap