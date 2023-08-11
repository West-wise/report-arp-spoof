#include "TargetUtil.h"


#pragma pack(push, 1)
struct EthArpPacket final {
        EthHdr eth_;
        ArpHdr arp_;
};
#pragma pack(pop)


Mac getTargetMac(pcap_t* handle, Mac myMac, Ip myIP, Ip TargetIp) {
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
    packet.arp_.tip_ = htonl(TargetIp);

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    std::string tmac;
    const u_char* pkt;
    struct pcap_pkthdr* header;
    struct EthHdr* Ethernet;
    struct ArpHdr* Arp;
    Mac Target_Mac_Addr; //Sender와 똑같다.
    while(true) {
        int res = pcap_next_ex(handle, &header, &pkt);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        Ethernet = (struct EthHdr *)(pkt);
        Arp = (struct ArpHdr *)(pkt + sizeof(EthHdr));
        if (Ethernet->type_ == htons(EthHdr::Arp) && Arp->op_ == htons(ArpHdr::Reply) && ntohl(Arp->sip_) == TargetIp){
            Target_Mac_Addr = Arp->smac_;
	    tmac = static_cast<std::string>(Target_Mac_Addr);
	    std::cout << "Target MAC Address: " << tmac << std::endl;	    
	    break;
        }
	else{
		printf("Wating Target MAC!\n");
	}
    }

    return Target_Mac_Addr;
}
