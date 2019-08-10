#pragma once

#ifndef SESSION_H
#define SESSION_H
class Session{
	private:
		int session_Num;
		char* smac;
		char* sip;
		char* tmac;
		char* tip;
		char* attack_mac;
		pcap_t* handle;
	public:
		Session(){}
		void handle_session();
		void set(int sn, char* sender_mac, char* sender_ip, char* target_mac, char* target_ip, pcap_t* handle, char* attacker_mac, struct Parameter_Pthread* pt);
};
#endif
