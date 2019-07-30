#include "stdafx.h"

ARP_header::ARP_header(){
	this->frame_type = htons(ARP_FRAME_TYPE);
	this->mac_type = htons(ETHER_MAC_TYPE);
	this->prot_type = htons(IP_PROTO_TYPE);
	this->mac_addr_size = ETH_MAC_ADDR_LEN;
	this->prot_addr_size = IP_ADDR_LEN;
	this->op = htons(OP_ARP_REQUEST);
}

void ARP_header::Print_ARP(){
	int count = 0;
	printf("Destination MAC = ");
	for(int i = 0; i < ETH_MAC_ADDR_LEN; i++){
		printf("%02x:", this->Destination_mac_addr[i]);
	}
	printf("\n");
	printf("Source MAC = ");
	for(int i = 0; i < ETH_MAC_ADDR_LEN; i++){
		printf("%02x:", this->src_mac_addr[i]);
	}
	printf("\n");
	printf("Sender MAC = ");
	for(int i = 0; i < ETH_MAC_ADDR_LEN; i++){
		printf("%02x:", this->sender_mac_addr[i]);
	}
	printf("\n");
	printf("Sender IP = ");
	for(int i = 0; i < IP_ADDR_LEN; i++){
		if(count == 1){
			printf(".");
			count = 0;
		}
		printf("%d", this->sender_ip_addr[i]);
		count++;
	}
	printf("\n");
	printf("Target MAC = ");
	for(int i = 0; i < ETH_MAC_ADDR_LEN; i++){
		printf("%02x:", this->target_mac_addr[i]);
	}
	printf("\n");
	printf("Target IP = ");
	count = 0;
	for(int i = 0; i < IP_ADDR_LEN; i++){
		if(count == 1){
			printf(".");
			count = 0;
		}
		printf("%0d", this->target_ip_addr[i]);
		count++;
	}
	printf("\n\n");
}


void ARP_header::die(char* str){
	fprintf(stderr, "%s\n", str);
	exit(1);
}

void ARP_header::tomar_ip_addr(struct in_addr* in_addr, char* str){
	struct hostent* hostp;

	in_addr->s_addr = inet_addr(str);
	if(in_addr->s_addr == -1){
		if((hostp = gethostbyname(str))){
			bcopy(hostp->h_addr, in_addr, hostp->h_length);
		}
		else{
			fprintf(stderr, "send_arp: unknown host [%s].\n", str);
			exit(1);
		}
	}
}

void ARP_header::tomar_mac_addr(u_char* buf, char* str){
	u_char c, val;

	for(int i = 0; i < ETH_MAC_ADDR_LEN; i++){
		//printf("%s\n", str);
		if(!(c = tolower(*str++))){
			//printf("%s\n", str);
			die("Invalid hardware address");
		}
		if(isdigit(c)) val = c - '0';
		else if(c >= 'a' && c <= 'f') val = c - 'a' + 10;
		else die("Invalid hardware address");

		*buf = val << 4;
		if(!(c = tolower(*str++))){
			//printf("%s\n", str);
			die("Invalid hardware address");
		}
		if(isdigit(c)) val = c - '0';
		else if(c >= 'a' && c <= 'f') val = c - 'a' + 10;
		else{
			//printf("%s\n", str);
			die("Invalid hardware address");
		}

		*buf++ |= val;

		if(*str == ':') str++;
	}
}




