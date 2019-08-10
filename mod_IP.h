#pragma once

#ifndef MOD_IP_H
#define MOD_IP_H
class IP_header{
        private:
        public:
                char WIP[2]; // what_is_protocol
                IP_header(){}
                char* Print_IP(const u_char* Packet_DATA);

};
#endif
