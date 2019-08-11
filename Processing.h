#pragma once

#ifndef PROCESSING_H
#define PROCESSING_H

struct Parameter_Pthread{
    int 	session_Number;
    char 	sip[16];
    char 	smac[13];
    char 	tip[16];
    char 	tmac[13];
    char   attack_mac[13];
    pcap_t* handle;
};

struct Info_mymac{
    char my_mac[13];
    char my_ip[16];
};

char* delChar(char* buf, char ch);
char* convert_mac(const char* data);
void* Attack(void* info);
struct Info_mymac* find_My_Mac();
void* find_Mac(void* info);
void* Manage_Session(void* info);
void Print_Data(const u_char* Packet_DATA);
void usage();

#endif
