#include "AttackerInfo.h"

#define MAC_ALEN 6
#define MAC_ADDR_LEN 6

//Attacker MAC function
Mac getMacAddress(const char *interfaceName) {
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP); // 소켓 생성

    ifreq ifr{}; // ifreq 구조체 생성
    strncpy(ifr.ifr_name, interfaceName, IFNAMSIZ); // 인터페이스 이름 설정
    ioctl(fd, SIOCGIFHWADDR, &ifr); // MAC 주소 가져오기
    close(fd); // 소켓 닫기

    uint8_t mac[MAC_ADDR_LEN]; // MAC 주소를 저장할 배열

    memcpy(mac, ifr.ifr_hwaddr.sa_data, MAC_ADDR_LEN); // MAC 주소 복사

    printf("Attacker Mac : ");
    for (int i = 0; i < MAC_ADDR_LEN; i++) {
        printf("%02X", mac[i]);
        if (i < MAC_ADDR_LEN - 1) {
            printf(":");
        }
    }
    printf("\n");

    return Mac(mac);
}



Ip getAttackerIp(const char *interfaceName) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0); // 소켓 생성

    ifreq ifr{}; // ifreq 구조체 생성
    strncpy(ifr.ifr_name, interfaceName, IFNAMSIZ); // 인터페이스 이름 설정
    ioctl(fd, SIOCGIFADDR, &ifr); // IP 주소 가져오기
    close(fd); // 소켓 닫기

    struct sockaddr_in* sockaddr = reinterpret_cast<struct sockaddr_in*>(&ifr.ifr_addr);
    char ipBuffer[INET_ADDRSTRLEN]; // IP 주소를 저장할 버퍼
    inet_ntop(AF_INET, &(sockaddr->sin_addr), ipBuffer, INET_ADDRSTRLEN); // IP 주소를 문자열로 변환하여 저장
    printf("Attacker Ip : %s\n",ipBuffer);

    
    return Ip(ipBuffer);
}


int GetMacAddress(const char *dev, uint8_t *mac_addr) {
    struct ifreq ifr;
    int sockfd, ret;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(sockfd < 0) {
        printf("Fail to get MAC Address");
        return -1;
    }

    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    ret = ioctl(sockfd, SIOCGIFHWADDR, &ifr);
    if(ret < 0) {
        printf("Fail to get Mac Address");
        close(sockfd);
        return -1;
    }

    memcpy(mac_addr, ifr.ifr_hwaddr.sa_data, MAC_ALEN);
    close(sockfd);

    return 0;
}
