#pragma once
#include "pch.h"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct MacIp {
	MacIp(){};
	MacIp(Mac mac, Ip ip){
		this->mac_ = mac;
		this->ip_ = ip;
	}
	Mac mac_;
	Ip ip_;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct MacIpSendTarget {
	MacIpSendTarget(MacIp sender, MacIp target) {
		this->sender_ = sender;
		this->target_ = target;
	};
	MacIp sender_;
	MacIp target_;
};
#pragma pack(pop)