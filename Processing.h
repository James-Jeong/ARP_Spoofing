#pragma once

#ifndef PROCESSING_H
#define PROCESSING_H

struct Parameter_Pthread{
	char* sip;
	char* smac;
	char* tip;
	char* tmac;
	pcap_t* handle;
};

void delChar(char* buf, char* dest, char ch);
void convert_mac(const char* data, char* cvrt_str, int s);
void* Attack(void* info);
void* find_My_Mac(void* info);
void* find_Mac(void* info);
void Print_Data(const u_char* Packet_DATA);
void usage();

#endif
