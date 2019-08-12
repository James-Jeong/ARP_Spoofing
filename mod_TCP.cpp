#include "stdafx.h"

int TCP_header::Print_TCP(const u_char* Packet_DATA){
    struct libnet_tcp_hdr* TH = (struct libnet_tcp_hdr*)(Packet_DATA);

    // TCP data offset check
    if(TH->th_off < 4) return 0;

    char sp[6];
    sprintf(sp, "%d", ntohs(TH->th_sport));

    char dp[6];
    sprintf(dp, "%d", ntohs(TH->th_dport));

    //printf("sp : %s\n", sp);
    //printf("dp : %s\n", dp);

    if((!strcmp(sp, "443")) || (!strcmp(dp, "443"))){
        printf("TCP SSL(HTTPS) protocol\n");
    }
    else if((!strcmp(sp, "25")) || (!strcmp(dp, "25"))){
        printf("TCP SMTP protocol\n");
    }
    else if((!strcmp(sp, "53")) || (!strcmp(dp, "53"))){
        printf("TCP DNS protocol\n");
    }
    else if((!strcmp(sp, "80")) || (!strcmp(dp, "80"))){
        printf("TCP HTTP protocol\n");
    }
    else if((!strcmp(sp, "22")) || (!strcmp(dp, "22"))){
        printf("TCP SSH protocol\n");
    }
    else if((!strcmp(sp, "23")) || (!strcmp(dp, "23"))){
        printf("TCP Telnet protocol\n");
    }
    else if((!strcmp(sp, "111")) || (!strcmp(dp, "111"))){
        printf("TCP RPC protocol\n");
    }

    printf("[Source] <Port> Number : %d\n", ntohs(TH->th_sport));
    printf("[Destination] <Port> Number : %d\n", ntohs(TH->th_dport));

    //free(sp); free(dp);
    return ((TH->th_off) * 4);
}
