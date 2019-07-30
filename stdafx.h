#pragma once

#ifndef STDAFX_H
#define STDAFX_H

#include <iostream>
#include <pcap.h>
#include <stdio.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>

#include "mod_ARP.h"

#include <netdb.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <linux/if_ether.h>

#include <libnet.h>
#include "libnet-headers.h"
#include "libnet-functions.h"
#include "libnet-macros.h"
#include "libnet-structures.h"
#include "libnet-types.h"

using namespace std;

#endif