#include "inet.h"

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>

int get_local_ip(char *dest, const char *interface_name) {
    struct ifaddrs *addrs, *tmp;
    getifaddrs(&addrs);
    tmp = addrs;

    while (tmp) {
        int iface_name_found = strcmp(tmp->ifa_name, interface_name);

        if (iface_name_found == 0 && tmp->ifa_name && tmp->ifa_addr && tmp->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in *addr = (struct sockaddr_in *)&tmp->ifa_addr;
            getnameinfo(tmp->ifa_addr, sizeof(struct sockaddr_in), dest, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
            break;
        }

        tmp = tmp->ifa_next;
    }

    freeifaddrs(addrs);
    return 0;
}

int resolve_hostname(const char* hostname, char* dest) {
    struct hostent *host = gethostbyname(hostname);
    if (host == NULL) {
        return 1;
    }

    const char *target = inet_ntoa(*((struct in_addr*)host->h_addr));
    memcpy(dest, target, strlen(target));
    return 0;
}

unsigned short check_sum(unsigned short *dgm, int bytes) {
    register long sum = 0;
    register short answer;
    unsigned int odd_byte;

    while(bytes > 1) {
        sum += *dgm++;
        bytes -= 2;
    }

    if(bytes == 1) {
        odd_byte = 0;
        *((unsigned char*)&odd_byte) = *(unsigned char*)dgm;
        sum += odd_byte;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    answer = (short)~sum;

    return answer;
}

