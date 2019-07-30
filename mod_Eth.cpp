#include "stdafx.h"

uint8_t Ethernet_header::Print_Eth(const u_char* Packet_DATA){
    struct libnet_ethernet_hdr* EH = (struct libnet_ethernet_hdr*)(Packet_DATA);
    uint8_t EH_length = (uint8_t)(sizeof(EH));
    u_short ethernet_type;
    ethernet_type = ntohs(EH->ether_type);

    if(ethernet_type != 0x0800){
        printf("Ethernet type is not IP\n");
        return 0;
    } // IP CHECK

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
    return EH_length;
}
