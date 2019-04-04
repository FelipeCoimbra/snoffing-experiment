#include "sniffing.h"

#include <stdlib.h>
#include <stdarg.h>

void exit_error(int code, ...) {
    va_list args;
    switch (code)
    {
        case 1:
            printf("Usage: sniffing <NETWORK INTERFACE> <FILTER SYNTAX>[optional]\n");
            break;
        
        case 2:
            printf("Error: Could not find device %s\n", args[1]);

        default:
            printf("Unknown error code: %d", code);
    }
    exit(code);
}

/*
    Args:
        1 - Network Interface identifier
        2 - Filter syntax
*/
int main(int argc, char* argv[]) {

    if (argc < 2) {
        exit_error(1);
    }

    //
    //  Network interface identification
    //
    char* net_interface = argv[1];
    
    //
    // BPF pcap syntax
    //
    char* filter_exp = NULL;

    if (argc > 2) {
        printf("oi");
        filter_exp = argv[2];
    }

    //
    // Pcap Session Setup
    //
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    // Step 1: Open live pcap session on NIC with name net_interface
    handle = pcap_open_live(net_interface, BUFSIZ, 1, 1000, errbuf);

    //
    //  BPF Setup
    //
    const char default_filter_exp[] = "ip";//"ip proto icmp";
    struct bpf_program fp;
    bpf_u_int32 net;

    // Step 2: Compile filter_exp into BPF psuedo-code
    pcap_compile(handle, &fp, filter_exp != NULL ? filter_exp : default_filter_exp, 0, net);
    pcap_setfilter(handle, &fp);
    
    // Step 3: Capture packets
    pcap_loop(handle, -1, simple_callback, NULL);

    //Close the handle
    pcap_close(handle);
    
    return 0;
}
