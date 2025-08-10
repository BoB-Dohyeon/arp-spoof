#pragma once
#include "pch.h"

extern const char *interface;

// 아래 2개의 함수는 외부 자료 참조

Mac get_attacker_mac(){
	int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		printf("Fail create socket.\n");
		return Mac();
	}

	ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);

	if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) {
		printf("Fail get mac address.\n");
		close(sockfd);
		return Mac();
	}

	close(sockfd);

	uint8_t mac_byte[6];
	memcpy(mac_byte, ifr.ifr_hwaddr.sa_data, 6);
 	Mac att_mac(mac_byte);
	return att_mac;
}

string get_attacker_ip() {
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd == -1) {
		printf("Fail get ip address.\n");
		exit(0);
	}

	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);

	if (ioctl(fd, SIOCGIFADDR, &ifr) == -1) {
		printf("Fail get ip address.\n");
		close(fd);
		exit(0);
	}

	close(fd);

	struct sockaddr_in* ipaddr = (struct sockaddr_in*)&ifr.ifr_addr;
	return inet_ntoa(ipaddr->sin_addr);
}