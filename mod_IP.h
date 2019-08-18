#pragma once

#ifndef MOD_IP_H
#define MOD_IP_H
class IP_header{
        private:
        public:
                char WIP[2]; // what_is_protocol
                IP_header(){}
                bool Check_IP(const u_char* Packet_DATA, char* sip, char* dip);
                char* Print_IP(const u_char* Packet_DATA);

};
#endif
