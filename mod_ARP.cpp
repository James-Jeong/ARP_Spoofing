#include "stdafx.h"

/*
this->mac_type = htons(ETHER_MAC_TYPE);
this->prot_type = htons(IP_PROTO_TYPE);
this->mac_addr_size = ETH_MAC_ADDR_LEN;
this->prot_addr_size = IP_ADDR_LEN;
this->op = htons(OP_ARP_REPLY);
*/

/*
this->mac_type = htons(ETHER_MAC_TYPE);
this->prot_type = htons(IP_PROTO_TYPE);
this->mac_addr_size = ETH_MAC_ADDR_LEN;
this->prot_addr_size = IP_ADDR_LEN;
this->op = htons(OP_ARP_REQUEST);
*/

void Print_ARP(struct ARP_header* a){
    int count = 0;
    printf("Destination MAC = ");
    for(int i = 0; i < ETH_MAC_ADDR_LEN; i++){
        printf("%02x:", a->Destination_mac_addr[i]);
    }
    printf("\n");
    printf("Source MAC = ");
    for(int i = 0; i < ETH_MAC_ADDR_LEN; i++){
        printf("%02x:", a->src_mac_addr[i]);
    }
    printf("\n");
    printf("Sender MAC = ");
    for(int i = 0; i < ETH_MAC_ADDR_LEN; i++){
        printf("%02x:", a->sender_mac_addr[i]);
    }
    printf("\n");
    printf("Sender IP = ");
    for(int i = 0; i < IP_ADDR_LEN; i++){
        if(count == 1){
            printf(".");
            count = 0;
        }
        printf("%d", a->sender_ip_addr[i]);
        count++;
    }
    printf("\n");
    printf("Target MAC = ");
    for(int i = 0; i < ETH_MAC_ADDR_LEN; i++){
        printf("%02x:", a->target_mac_addr[i]);
    }
    printf("\n");
    printf("Target IP = ");
    count = 0;
    for(int i = 0; i < IP_ADDR_LEN; i++){
        if(count == 1){
            printf(".");
            count = 0;
        }
        printf("%0d", a->target_ip_addr[i]);
        count++;
    }
    printf("\n\n");
}


void EndOfProgram(char* str){
    fprintf(stderr, "%s\n", str);
    exit(1);
}

void tomar_ip_addr(struct in_addr* in_addr, char* str){
    //printf("str : %s\n", str);
    inet_aton(str, in_addr);
    //int a = inet_aton(str, in_addr);
    //printf("a : %d\n", a);
}

void tomar_mac_addr(u_char* buf, char* str){
    u_char c, val;
    char* error_msg = "Wrong mac addr";

    for(int i = 0; i < ETH_MAC_ADDR_LEN; i++){
        if(!(c = tolower(*str++))){
            //printf("%s\n", str);
            EndOfProgram(error_msg);
        }
        if(isdigit(c)) val = c - '0';
        else if(c >= 'a' && c <= 'f') val = c - 'a' + 10;
        else EndOfProgram(error_msg);

        *buf = val << 4;
        if(!(c = tolower(*str++))){
            //printf("%s\n", str);
            EndOfProgram(error_msg);
        }
        if(isdigit(c)) val = c - '0';
        else if(c >= 'a' && c <= 'f') val = c - 'a' + 10;
        else{
            //printf("%s\n", str);
            EndOfProgram(error_msg);
        }

        *buf++ |= val;
        if(*str == ':') str++;
    }
}

void check_ARP(const u_char* Packet_DATA){
    struct ARP_header* ah = (struct ARP_header*)(Packet_DATA);
    if((int)htons(ah->prot_type) == 2048){
        //printf("ah->mac_type : %x\n", htons(ah->mac_type));
        printf("ah->prot_type : %d\n", htons(ah->prot_type));
        //printf("ah->mac_addr_size : %x\n", htons(ah->mac_addr_size));
        //printf("ah->prot_addr_size : %x\n", htons(ah->prot_addr_size));
        printf("ah->op : %d\n", htons(ah->op));
        //printf("ah->sender_ip_addr : %d\n", ah->sender_ip_addr[0]);
        //printf("ah->sender_ip_addr : %d\n", ah->sender_ip_addr[1]);
        //printf("ah->sender_ip_addr : %d\n", ah->sender_ip_addr[2]);
        //printf("ah->sender_ip_addr : %d\n", ah->sender_ip_addr[3]);
    }
    else { printf("Packet is not ARP\n"); return ; }

    if((int)htons(ah->op) != 2){
        printf("ARP packet is not Reply\n");
        return ; // reply : 2
    }
    else{
        printf("ah->sender_mac_addr : %x\n", ah->sender_mac_addr[0]);
        printf("ah->sender_mac_addr : %x\n", ah->sender_mac_addr[1]);
        printf("ah->sender_mac_addr : %x\n", ah->sender_mac_addr[2]);
        printf("ah->sender_mac_addr : %x\n", ah->sender_mac_addr[3]);
        printf("ah->sender_mac_addr : %x\n", ah->sender_mac_addr[4]);
        printf("ah->sender_mac_addr : %x\n", ah->sender_mac_addr[5]);
    }
}


