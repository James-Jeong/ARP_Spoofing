#include "stdafx.h"
#include "mod_UDP.h"

int UDP_header::Print_UDP(const u_char* Packet_DATA){
    struct libnet_udp_hdr* UH = (struct libnet_udp_hdr*)(Packet_DATA);

    char* sp = (char*)malloc(sizeof(UH->uh_sport));
    sprintf(sp, "%d", ntohs(UH->uh_sport));
    char* dp = (char*)malloc(sizeof(UH->uh_dport));
    sprintf(dp, "%d", ntohs(UH->uh_dport));

    //printf("sp : %s\n", sp);
    //printf("dp : %s\n", dp);

    if((!strcmp(sp, "80")) || (!strcmp(dp, "80"))){
        printf("UDP HTTP protocol\n");
    }
    else if((!strcmp(sp, "161")) || (!strcmp(dp, "161"))){
        printf("UDP SNMP protocol\n");
    }
    else if((!strcmp(sp, "111")) || (!strcmp(dp, "111"))){
        printf("UDP RPC protocol\n");
    }

    printf("[Source] <Port> Number : %d\n", ntohs(UH->uh_sport));
    printf("[Destination] <Port> Number : %d\n", ntohs(UH->uh_dport));

    printf("UDP Length : %x\n", UH->uh_ulen);
    printf("UDP checksum : %x\n", UH->uh_sum);

    return (UH->uh_ulen);
}
