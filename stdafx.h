#pragma once

#ifndef STDAFX_H
#define STDAFX_H

#include <pcap.h>
#include <stdio.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <string.h>
#include <string>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>
#include <vector>
#include <pthread.h>
#include <signal.h>

#include "mod_UDP.h"
#include "mod_TCP.h"
#include "mod_IP.h"
#include "mod_Eth.h"
#include "mod_ARP.h"
#include "Processing.h"
#include "Session.h"

#include <netdb.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <linux/if_ether.h>

#include <libnet.h>
#include "libnet-headers.h"
#include "libnet-functions.h"
#include "libnet-macros.h"
#include "libnet-structures.h"
#include "libnet-types.h"

#define MAX_PAC_SIZE 100
#define REQ_CNT 20
#define PTHREAD_NUM 50
#define SESSION_NUM 20

#endif
