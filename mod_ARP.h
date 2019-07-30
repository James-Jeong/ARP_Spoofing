#pragma once

#ifndef MOD_ARP_H
#define MOD_ARP_H

#define ETH_MAC_ADDR_LEN 6
#define IP_ADDR_LEN 4
#define ETHER_MAC_TYPE 1
#define OP_ARP_REQUEST 2
#define ARP_FRAME_TYPE 0x0806
#define IP_PROTO_TYPE 0x0800
#define DEFAULT_DEVICE "enp0s3"

class ARP_header{
	private:
	public:
		u_char Destination_mac_addr[ETH_MAC_ADDR_LEN];
		u_char src_mac_addr[ETH_MAC_ADDR_LEN];
		u_short frame_type;
		u_short mac_type;
		u_short prot_type;
		u_char mac_addr_size;
		u_char prot_addr_size;
		u_short op;
		u_char sender_mac_addr[ETH_MAC_ADDR_LEN];
		u_char sender_ip_addr[IP_ADDR_LEN];
		u_char target_mac_addr[ETH_MAC_ADDR_LEN];
		u_char target_ip_addr[IP_ADDR_LEN];
		u_char padding[18];

		ARP_header();
		void Print_ARP();
		void die(char* str);
		void tomar_ip_addr(struct in_addr* sender, char* str);
		void tomar_mac_addr(u_char* buf, char* str);
};

#endif
