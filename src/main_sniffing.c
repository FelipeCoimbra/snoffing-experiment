#include "sniffing.h"

#include <stdlib.h>
#include <string.h>

void exit_error(int code, ...) {
    va_list args;
    switch (code)
    {
        case 1:
            printf("Usage: sniffing <NETWORK INTERFACE> <FILTER SYNTAX>[optional]\n");
            break;
        
        case 2:
            printf("Error: Could not find device %s\n", args[1]);
            break;

        default:
            printf("Unknown error code: %d", code);
    }
    exit(code);
}

/*
    Returns a callback function to process sniffed packets according to the user choice
*/
void (*pick_callback(const char* user_callback))(u_char *, const struct pcap_pkthdr *, const u_char *) {
    // Sample callback function
    if (user_callback == NULL || strlen(user_callback) == 0){
         return simple_callback;
    }
    return print_proto_src_dst;
}

/*
    Args:
        1 - Network Interface identifier
        2 - Filter syntax
        3 - Sniffer callback
*/
int main(int argc, char* argv[]) {

    if (argc < 2) {
        exit_error(1);
    }

    //
    //  User's Network interface identification
    //
    char* net_interface = argv[1];
    
    //
    // User's BPF pcap syntax
    //
    const char* user_filter_exp = NULL;
    if (argc > 2) {
        user_filter_exp = argv[2];
    }

    //
    //  User's specified sniffer callback function
    //
    const char* user_callback = NULL;
    if (argc > 3) {
        user_callback = argv[3];
    }

    //
    // Pcap Session Setup
    //
    pcap_t *handle;                // Pcap handler
    char errbuf[PCAP_ERRBUF_SIZE]; // Buffer for error messages

    //
    //  BPF Setup
    //
    const char default_filter_exp[] = "ip proto tcp";
    struct bpf_program fp;
    bpf_u_int32 net;

    // Decide which filter expression to use
    const char* filter_exp = default_filter_exp;
    if (user_filter_exp != NULL && strlen(user_filter_exp) > 0){
        filter_exp = user_filter_exp;
    }

    /////////////////////////////////////////////////////////////////
    //
    // Step 1: Open live pcap session on NIC with name net_interface
    //
    handle = pcap_open_live(net_interface, BUFSIZ, 1, 1000, errbuf);

    /////////////////////////////////////////////////////////////////
    //
    // Step 2: Compile filter_exp into BPF pseudo-code
    //
    pcap_compile(handle, &fp, filter_exp, 0, net);
    pcap_setfilter(handle, &fp);
    
    /////////////////////////////////////////////////////////////////
    //
    // Step 3: Capture packets
    //
    pcap_loop(handle, -1, pick_callback(user_callback), NULL);

    //Close the handle
    pcap_close(handle);
    
    return 0;
}
