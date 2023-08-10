#pragma once

#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"

//include for MAC
#include <iostream>
#include <cstdlib>
#include <string>

#include "mac.h"
#include "ip.h"


Mac getTargetMac(pcap_t* handle, Mac myMac , Ip myIP, Ip TargetIp);