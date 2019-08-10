#pragma once

#ifndef MOD_ETH_H
#define MOD_EHT_H
class Ethernet_header{
        private:
        public:
                Ethernet_header(){}
                void Change_Mac(const u_char* Packet_DATA, char* sender_mac);
                uint8_t Print_Eth(const u_char* Packet_DATA);
                int Check_Eth(const u_char* Packet_DATA, char* sender_mac, char* target_mac, char* my_mac);

};
#endif
