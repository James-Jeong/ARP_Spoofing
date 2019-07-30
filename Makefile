all: ARP_S

ARP_S: ARP_S.o mod_Eth.o mod_IP.o mod_TCP.o mod_UDP.o mod_ARP.o
	gcc -o ARP_S ARP_S.o mod_Eth.o mod_IP.o mod_TCP.o mod_UDP.o mod_ARP.o -lpcap -lpthread

ARP_S.o: main.cpp
	gcc -c -o ARP_S.o main.cpp

mod_Eth.o: mod_Eth.cpp
	gcc -c -o mod_Eth.o mod_Eth.cpp

mod_IP.o: mod_IP.cpp
	gcc -c -o mod_IP.o mod_IP.cpp

mod_TCP.o: mod_TCP.cpp
	gcc -c -o mod_TCP.o mod_TCP.cpp

mod_UDP.o: mod_UDP.cpp
	gcc -c -o mod_UDP.o mod_UDP.cpp

mod_ARP.o: mod_ARP.cpp
	gcc -c -o mod_ARP.o mod_ARP.cpp

clean:
	rm -f *.o
	rm -f ARP_S

.PHONY : clean

