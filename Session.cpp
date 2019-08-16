#include "stdafx.h"
#include "Session.h"

void Session::set(int sn, char* sender_mac, char* sender_ip, char* target_mac, char* target_ip, pcap_t* handle, char* attacker_mac, struct Parameter_Pthread* pt, pthread_t thread){
    this->session_Num = sn;

    memcpy(this->sip, sender_ip, 16);
    memcpy(this->smac, sender_mac, 12);
    this->smac[13] = '\0';

    memcpy(this->tip, target_ip, 16);
    memcpy(this->tmac, target_mac, 12);
    this->tmac[13] = '\0';

    memcpy(this->attack_mac, attacker_mac, 12);
    this->attack_mac[13] = '\0';

    this->handle = handle;
    pthread_create(&thread, NULL, Attack, (void*)(pt));
    pthread_detach(thread);
}
