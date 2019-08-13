#include "stdafx.h"

int Ethernet_header::Check_Eth(const u_char* Packet_DATA, char* sender_mac, char* target_mac, char* my_mac){
    int sum = 0;
    struct libnet_ethernet_hdr* EH = (struct libnet_ethernet_hdr*)(Packet_DATA);

    char EH_smac[13];
    //char* EH_smac = (char*)malloc(13);
    //if(EH_smac == NULL){ perror("EH_smac malloc error"); exit(1); }
    sprintf(EH_smac, "%02x%02x%02x%02x%02x%02x",
        EH->ether_shost[0],
        EH->ether_shost[1],
        EH->ether_shost[2],
        EH->ether_shost[3],
        EH->ether_shost[4],
        EH->ether_shost[5]);

    char EH_dmac[13];
    //char* EH_dmac = (char*)malloc(13);
    //if(EH_dmac == NULL){ perror("EH_dmac malloc error"); exit(1); }
    sprintf(EH_dmac, "%02x%02x%02x%02x%02x%02x",
        EH->ether_dhost[0],
        EH->ether_dhost[1],
        EH->ether_dhost[2],
        EH->ether_dhost[3],
        EH->ether_dhost[4],
        EH->ether_dhost[5]);

    //printf("EH_smac : %s\n", EH_smac);
    //printf("EH_dmac : %s\n", EH_dmac);
    printf("sender mac : %s\n", sender_mac);
    //printf("target mac : %s\n", target_mac);
    printf("attacker_mac : %s\n", my_mac);

    // Is sender mac address equal to EH's mac address?
    if(strncmp(sender_mac, EH_smac, strlen(sender_mac)) == 0){
        //printf("sender_mac == EH_smac\n");
        sum += 1;
    }
    if(strncmp(my_mac, EH_dmac, strlen(my_mac)) == 0){
        //printf("attac_mac == EH_dmac\n");
        sum += 1;
    }
    else if(strncmp(EH_dmac, "ffffffffffff", strlen(EH_dmac)) == 0){
        //printf("EHDMAC : %s\n", EH_dmac);
        //printf("ffffffffffff == EH_dmac\n");
        sum += 10;
    }
    else if(strncmp(EH_dmac, target_mac, strlen(EH_dmac)) == 0){
        //printf("target_mac == EH_dmac\n");
        sum += 100;
    }
    //free(EH_dmac); free(EH_smac);
    return sum;
}
// if return 2, Success to find spoofed packet
// else if return 3, Success to find broadcast packet sended by sender

uint8_t Ethernet_header::Print_Eth(const u_char* Packet_DATA){
    struct libnet_ethernet_hdr* EH = (struct libnet_ethernet_hdr*)(Packet_DATA);
    uint8_t result = 0;
    //uint8_t EH_length = (uint8_t)(sizeof(EH));
    u_short ethernet_type;
    ethernet_type = ntohs(EH->ether_type);
    if(ethernet_type == 0x0800){
        printf("[ ----------_IP_---------- ]\n");
        result = 1;
    }
    else if(ethernet_type == 0x0806){
        printf("[ ----------_ARP_---------- ]\n");
        result = 2;
    }
    else{
        printf("[ ----------_Unknown Ethernet Type_---------- ]\n");
        return 0;
    }
    printf("[Source] <MAC> Address : %02x:%02x:%02x:%02x:%02x:%02x:\n",
        EH->ether_shost[0],
        EH->ether_shost[1],
        EH->ether_shost[2],
        EH->ether_shost[3],
        EH->ether_shost[4],
        EH->ether_shost[5]);

    printf("[Destination] <MAC> Address : %02x:%02x:%02x:%02x:%02x:%02x:\n",
        EH->ether_dhost[0],
        EH->ether_dhost[1],
        EH->ether_dhost[2],
        EH->ether_dhost[3],
        EH->ether_dhost[4],
        EH->ether_dhost[5]);
    return result;
}
