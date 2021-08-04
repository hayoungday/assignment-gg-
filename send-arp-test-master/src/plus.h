#ifndef PLUS_H
#define PLUS_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <signal.h>
#include <errno.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "ip.h"
#include <pcap.h>
#include <stdbool.h>
#include "ethhdr.h"
#include "arphdr.h"


#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

#endif // PLUS_H
