#include "stdafx.h"

int Ethernet_header::Check_Eth(const u_char* Packet_DATA, char* sender_mac, char* target_mac, char* my_mac){
	int sum = 0;
	struct libnet_ethernet_hdr* EH = (struct libnet_ethernet_hdr*)(Packet_DATA);
	u_short ethernet_type;
	ethernet_type = ntohs(EH->ether_type);
	if(ethernet_type == 0x0800){
		printf("Ethernet type is IP\n");
	}
	else if(ethernet_type == 0x0806){
		printf("Ethernet type is ARP\n");
	}
	else{
		printf("Warning: Unknown Ethernet type!\n");
		return 0;
	}

	char* EH_smac = (char*)malloc(sizeof(sender_mac));
	if(EH_smac == NULL){ perror("EH_smac malloc error"); exit(1); }
	sprintf(EH_smac, "%02x%02x%02x%02x%02x%02x",
		EH->ether_shost[0],
		EH->ether_shost[1],
		EH->ether_shost[2],
		EH->ether_shost[3],
		EH->ether_shost[4],
		EH->ether_shost[5]);

	char* EH_dmac = (char*)malloc(sizeof(target_mac));
	if(EH_dmac == NULL){ perror("EH_dmac malloc error"); exit(1); }
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
		sum += 1;
	}
	if(strncmp(my_mac, EH_dmac, strlen(my_mac)) == 0){
		sum += 1;
	}
	else if(strncmp(EH_dmac, "ffffffffffff", strlen(EH_dmac))){
		sum += 2;
	}
	else if(strncmp(EH_dmac, target_mac, strlen(EH_dmac))){
		sum += 3;
	}
	return sum;
}
// if return 2, Success to find spoofed packet
// else if return 3, Success to find broadcast packet sended by sender

uint8_t Ethernet_header::Print_Eth(const u_char* Packet_DATA){
	struct libnet_ethernet_hdr* EH = (struct libnet_ethernet_hdr*)(Packet_DATA);
	uint8_t EH_length = (uint8_t)(sizeof(EH));
	u_short ethernet_type;
	ethernet_type = ntohs(EH->ether_type);
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
