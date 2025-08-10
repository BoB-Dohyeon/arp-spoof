#pragma once

#include "pch.h"
#include "mac.h"

enum eth_header: uint16_t {
	ip4 = 0x0800,
	arp = 0x0806,
	ip6 = 0x86DD
};

#pragma pack(push, 1)
struct EthHdr final {
	Mac dmac_;
	Mac smac_;
	uint16_t type_;
};
#pragma pack(pop)
