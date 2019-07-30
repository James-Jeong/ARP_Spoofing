#pragma once

#ifndef MOD_ETH_H
#define MOD_EHT_H
class Ethernet_header{
	private:
	public:
		Ethernet_header(){}
		uint8_t Print_Eth(const u_char* Packet_DATA);

};
#endif
