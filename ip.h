#pragma once
#include "pch.h"

// arp-send-test 내에 있던 내용을 참고 및 삭제
// 개인적으로 추가하고 싶은 것들 추가 (int_8_to_32, print, compare)

struct Ip {
public:
	static const int size = 4;
	
	Ip() {};

	Ip(const uint8_t* int_ip) { memcpy(this->ip_, int_ip, this->size); }

	// input 예시 : "123.1.23.1"
	Ip(const string str_ip) {
		uint8_t iter = 0;
		uint8_t data = 0;
		for(int i = 0; i < str_ip.size(); i++){
			if('0' <= str_ip[i] && str_ip[i] <= '9'){
				data = data * 10 + ((uint8_t)(str_ip[i]) - '0');
			}
			else if (str_ip[i] == '.' || str_ip[i] == '\n' || str_ip[i] == ' '){
				ip_[iter] = data;
				data = 0;
				iter += 1; 
			}
		}
		ip_[iter] = data;

	}

	uint32_t int_8_to_32();
	void print();
	bool compare(Ip com);

protected:
	uint8_t ip_[size];
};