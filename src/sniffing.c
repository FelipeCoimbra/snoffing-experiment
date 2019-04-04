
#include "sniffing.h"

#include <time.h>
#include <stdio.h>


/* This function will be invoked by pcap for each captured packet.
    This simple callback only alerts upon receipt and register the receipt time
*/
void simple_callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    time_t raw_time;
    struct tm* current_time;

    // Fill time and convert to local time zone
    time(&raw_time);
    current_time = localtime(&raw_time);

    // Print message
    printf("[%d:%d:%d] Got a packet!\n", current_time->tm_hour, current_time->tm_min, current_time->tm_sec);
}