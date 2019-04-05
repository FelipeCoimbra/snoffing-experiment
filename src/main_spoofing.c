#include "spoofing.h"

#include <sys/socket.h>
#include <netinet/ip.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define BUFFER_SIZE 1024

void exit_error(int code, ...) {
    va_list args;
    switch (code)
    {
        case 2:
            printf("Error: Invalid protocol \"%s\"\n", args[1]);
        case 1:
            printf("Usage: spoofing <DESTINATION IP> <PROTOCOL>(icmp|udp) <CONTENT>[optional]\n");
            break;
        
        case 3:
            printf("Error: Could not create raw socket\n");
            break;
        
        default:
            printf("Unknown error code: %d", code);
    }
    exit(code);
}

void verify_protocol(const char *protocol) {
    if (protocol == NULL || strlen(protocol) == 0) {
        exit_error(1);
    }

    if (strcmp(protocol, "icmp") != 0 && strcmp(protocol, "udp") != 0 ) {
        exit_error(2, protocol);
    }
}

/*
    Args:
        1 - Spoof packet destination IP address
        2 - Spoof packet protocol
        3 - Spoof packet content
*/
int main(int argc, char *argv[]) {

    if (argc < 3) {
        exit_error(1);
    }

    //
    // User chosen IP destination
    //
    const char* destination = argv[1];

    //
    //  User chosen protocol
    //
    const char* protocol = argv[2];
    verify_protocol(protocol);

    char buffer[BUFFER_SIZE] = "Some data";
    //
    // User content
    //
    if (argc > 4) {
        strncpy(buffer, argv[3], BUFFER_SIZE);
    }

    int socket_desc;
    socket_desc = socket(AF_INET,       // IPv4
                        SOCK_RAW,       // Specify raw socket (Nor TCP nor UDP)
                        IPPROTO_RAW);   // Raw IP protocol, i.e we provide the IP header, dont let kernel mess with it
    if (socket_desc < 0) {
        exit_error(3);
    }

    ///////////////////////////////////////////////////////////////
    //
    //  Spoof packets
    //
    int count = 1;
    while(1) {
        spoof(socket_desc, destination, protocol, buffer);
        printf("Sent spoof packet number %d\n", count++);
        sleep(1);
    }

    return 0;
}