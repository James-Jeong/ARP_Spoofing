#pragma once

#ifndef MOD_ARP_H
#define MOD_ARP_H

#define ETH_MAC_ADDR_LEN 6
#define IP_ADDR_LEN 4
#define ETHER_MAC_TYPE 1
#define OP_ARP_REPLY 2
#define OP_ARP_REQUEST 1
#define ARP_FRAME_TYPE 0x0806
#define IP_PROTO_TYPE 0x0800
#define DEFAULT_DEVICE "enp0s3"

// Destination_mac_addr : victim's mac address or gateway's mac address
// src_mac_addr : attacker's mac address
// sender_mac_addr : attacker's mac address
// sender_ip_addr : attacker's ip address
// target_mac_addr : victim's mac address
// target_ip_addr : victim's ip address

struct ARP_header{
        u_char Destination_mac_addr[ETH_MAC_ADDR_LEN];
        u_char src_mac_addr[ETH_MAC_ADDR_LEN];
        u_short frame_type;
        u_short mac_type;
        u_short prot_type;
        u_char mac_addr_size;
        u_char prot_addr_size;
        u_short op;
        u_int8_t sender_mac_addr[ETH_MAC_ADDR_LEN];
        u_int8_t sender_ip_addr[IP_ADDR_LEN];
        u_int8_t target_mac_addr[ETH_MAC_ADDR_LEN];
        u_int8_t target_ip_addr[IP_ADDR_LEN];
        u_char padding[18];
};

void Print_ARP(struct ARP_header* a);
void EndOfProgram(char* str);
void tomar_ip_addr(struct in_addr* sender, char* str);
void tomar_mac_addr(u_char* buf, char* str);
void check_ARP(const u_char* Packet_DATA);

#endif
