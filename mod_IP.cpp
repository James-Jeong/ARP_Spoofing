#include "stdafx.h"

bool IP_header::Check_IP(const u_char* Packet_DATA, char* sip, char* dip, char* attack_ip){
    struct libnet_ipv4_hdr* IH = (struct libnet_ipv4_hdr*)(Packet_DATA);
    int a = 0;
    if((a = strncmp(inet_ntoa(IH->ip_dst), attack_ip, strlen(attack_ip))) == 0){
        return true;
    }
    else if(((a = strncmp(inet_ntoa(IH->ip_src), sip, strlen(sip))) == 0) ||
            ((a = strncmp(inet_ntoa(IH->ip_dst), dip, strlen(dip))) == 0)){
        return true;
    }
    return false;
}

char* IP_header::Print_IP(const u_char* Packet_DATA){
    struct libnet_ipv4_hdr* IH = (struct libnet_ipv4_hdr*)(Packet_DATA);

    // IP Check
    if(IH->ip_hl == 0) return NULL;
    if(IH->ip_v < 4 && IH->ip_v > 9) return NULL;
    // 4 : IP
    // 5 : ST
    // 6 : SIP, SIPP, IPv6
    // 7 : TP/IX
    // 8 : PIP
    // 9 : TUBA

    printf("Type of service : %d\n", IH->ip_tos);
    printf("Total length : %d\n", IH->ip_len);
    printf("Identification : %x\n", IH->ip_id);
    printf("TTL : %d\n", IH->ip_ttl);
    printf("protocol : %x\n", IH->ip_p);
    printf("Checksum : %x\n", IH->ip_sum);

    sprintf(WIP, "%x", IH->ip_p);
    printf("WIP : %s\n", WIP);

    printf("[Source] <IP> Address : %s\n", inet_ntoa(IH->ip_src));
    printf("[Destination] <IP> Address : %s\n", inet_ntoa(IH->ip_dst));

    return WIP;
}
