#pragma once

#ifndef PROCESSING_H
#define PROCESSING_H

struct Parameter_Pthread{
    int 	session_Number;
    char* 	sip;
    char* 	smac;
    char* 	tip;
    char* 	tmac;
    pcap_t* handle;
};

struct Info_mymac{
    char* my_mac;
    char* my_ip;
};

char* delChar(char* buf, char ch);
char* convert_mac(const char* data);
void* Attack(void* info);
struct Info_mymac* find_My_Mac();
void* find_Mac(void* info);
void Print_Data(const u_char* Packet_DATA);
void usage();

#endif
