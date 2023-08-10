#pragma once

#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <iostream>
#include <cstdlib>
#include <string>
#include "mac.h"
#include "ip.h"

#pragma pack(push, 1)
struct EthArpPacket final {
        EthHdr eth_;
        ArpHdr arp_;
};
#pragma pack(pop)


Mac getSenderMac( pcap_t* handle, Mac myMAc , Ip myIP, Ip senderIp);

EthArpPacket Sender_Infection(const char *interfaceName,Mac my_mac,Mac SenderMac, Ip sip,Ip tip);



