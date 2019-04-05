#ifndef __SPOOFING_H__
#define __SPOOFING_H__

#include <sys/types.h>

void spoof(int sock_desc, const char* dest_ip, const char* proto, const char* content);

#endif