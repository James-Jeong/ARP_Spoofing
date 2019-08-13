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

/*void Session::handle_session(){
    struct Parameter_Pthread* pt3 = (struct Parameter_Pthread*)malloc(sizeof(struct Parameter_Pthread));

    strncpy(pt3->attack_mac, this->attack_mac, 12);
    strncpy(pt3->sip, this->sip, 16);
    strncpy(pt3->smac, this->smac, 12);
    strncpy(pt3->tip, this->tip, 16);
    strncpy(pt3->tmac, this->tmac, 12);

    pt3->handle = this->handle;
    pt3->session_Number = this->session_Num;

    Manage_Session(pt3);
}
*/
