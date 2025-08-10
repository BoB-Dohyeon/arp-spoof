#pragma once

#include "pch.h"
#include "mac.h"
#include "ip.h"

enum HWType: uint16_t { // 해당 부분은 그대로 남김
	NETROM = 0, // from KA9Q: NET/ROM pseudo
	ETHER = 1, // Ethernet 10Mbps
	EETHER = 2, // Experimental Ethernet
	AX25 = 3, // AX.25 Level 2
	PRONET = 4, // PROnet token ring
	CHAOS = 5, // Chaosnet
	IEEE802 = 6, // IEEE 802.2 Ethernet/TR/TB
	ARCNET = 7, // ARCnet
	APPLETLK = 8, // APPLEtalk
	LANSTAR = 9, // Lanstar
	DLCI = 15, // Frame Relay DLCI
	ATM = 19, // ATM
	METRICOM = 23, // Metricom STRIP (new IANA id)
	IPSEC = 31 // IPsec tunnel
};

enum OP: uint16_t { // 여기서는 현재 사용하는 부분만 남김
	Request = 1,
	Reply = 2, 
};

#pragma pack(push, 1)
struct ArpHdr final { // 이름도 그대로 남김
public:
    uint16_t hrd_;
	uint16_t pro_;
	uint8_t hln_;
	uint8_t pln_;
	uint16_t op_;
	Mac smac_;
	Ip sip_;
	Mac tmac_;
	Ip tip_;
};
#pragma pack(pop)
