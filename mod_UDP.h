#pragma once

#ifndef MOD_UDP_H
#define MOD_UDP_H
class UDP_header{
	private:
	public:
		UDP_header(){}
		int Print_UDP(const u_char* Packet_DATA);
};
#endif
