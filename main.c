#include "inet.h"

#include <netinet/in.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>

struct sockaddr_in daddr;

struct pseudo_header {
    unsigned int source_address;
    unsigned int dest_address;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short tcp_length;
};

void* receive_syn_ack();
int send_syn(int sock, in_addr_t saddr, int port);

int main(int argc, char **argv) {
    if (argc != 4) {
        printf("usage: scanner <interface> <host> <port>\n");
        return 1;
    }

    const char *interface = argv[1];
    const char *target = argv[2];
    int port = atoi(argv[3]);

    char source[17];
    memset(source, 0, 17);
    if (get_local_ip(source, interface)) {
        printf("error code %d: could not get local ip: %s\n", errno, strerror(errno));
        return 1;
    }

    char target_ip[17];
    memset(target_ip, 0, 17);
    if (resolve_hostname(target, target_ip)) {
        printf("could not resolve host name\n");
        return 1;
    }

    daddr.sin_family = AF_INET;
    daddr.sin_port = htons(port);
    daddr.sin_addr.s_addr = inet_addr(target_ip);

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) {
        printf("could not create socket\n");
        return 1;
    }

    pthread_t sniffer_thread;
    if (pthread_create(&sniffer_thread, NULL, receive_syn_ack, NULL) < 0) {
        printf("error code %d: could not create sniffer thread: %s\n", errno, strerror(errno));
        return 1;
    }

    int val = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &val, sizeof(val)) < 0) {
        printf("error code %d: could not set socket option: %s\n", errno, strerror(errno));
        return 1;
    }

    int bytes_sent = send_syn(sock, inet_addr(source), port);
    if (bytes_sent < 0) {
        printf("error code %d: could not send raw packet: %s\n", errno, strerror(errno));
        return 1;
    }

    pthread_join(sniffer_thread, NULL);
    return 0;
}

void* receive_syn_ack() {
    while (1) {
        int rsock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        if (rsock < 0) {
            printf("error code %d: could not receive ack: %s\n", errno, strerror(errno));
            return NULL;
        }

        struct sockaddr_in saddr;
        socklen_t saddr_size = sizeof(saddr);
        unsigned char* buffer = (unsigned char *)malloc(65536);
        socklen_t data_size = recvfrom(rsock, buffer, 65536, 0, (struct sockaddr *)&saddr, &saddr_size);
        if (data_size < 0) {
            printf("error code %d: could not receive ack: %s\n", errno, strerror(errno));
            return NULL;
        }

        struct iphdr *iph = (struct iphdr *)buffer;
        struct tcphdr *tcph = (struct tcphdr *)(buffer + iph->ihl * 4);
        char source_host[17], dest_host[17];
        inet_ntop(AF_INET, &iph->saddr, source_host, 17);
        inet_ntop(AF_INET, &iph->daddr, dest_host, 17);

        if (iph->saddr == daddr.sin_addr.s_addr && tcph->source == daddr.sin_port) {
            printf("%s:%d/tcp", inet_ntoa(daddr.sin_addr), ntohs(tcph->source));

            if (tcph->syn == 1 && tcph->ack == 1) {
                printf(" open\n");
            } else {
                printf(" closed\n");
            }

            close(rsock);
            break;
        }

        close(rsock);
    }

    return NULL;
}

int send_syn(int sock, in_addr_t saddr, int port) {
    char datagram[4096];
    memset(datagram, 0, 4096);

    struct iphdr *iph = (struct iphdr *)datagram;
    iph->version = 4;
    iph->ihl = 5;
    iph->tos = 0;
    iph->tot_len = sizeof(struct ip) + sizeof(struct tcphdr);
    iph->id = htons(7238);
    iph->frag_off = htons(16384);
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;
    iph->saddr = saddr;
    iph->daddr = daddr.sin_addr.s_addr;
    iph->check = check_sum((unsigned short *)datagram, iph->tot_len);

    struct tcphdr *tcph = (struct tcphdr *)(datagram + sizeof(struct iphdr));
    tcph->source = htons(12345);
    tcph->dest = htons(port);
    tcph->seq = htonl(1105024978);
    tcph->ack_seq = 0;
    tcph->doff = 5;
    tcph->urg = 0;
    tcph->ack = 0;
    tcph->psh = 0;
    tcph->rst = 0;
    tcph->syn = 1;
    tcph->fin = 0;
    tcph->window = htons(14600);
    tcph->check = 0;
    tcph->urg_ptr = 0;

    struct pseudo_header psh;
    psh.source_address = saddr;
    psh.dest_address = daddr.sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr));

    int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
    char *pseudogram = malloc (psize);
    memcpy(pseudogram, (char*)&psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr));

    tcph->check = check_sum((unsigned short *)pseudogram, psize);

    return sendto(sock, datagram, sizeof(struct iphdr) + sizeof(struct tcphdr), 0, (struct sockaddr*)&daddr, sizeof(daddr));
}
