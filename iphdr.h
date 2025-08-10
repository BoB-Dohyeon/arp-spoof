#pragma once

#include "pch.h"
#include "mac.h"
#include "ip.h"

#pragma pack(push, 1)
struct IpHdr final {
public:
    uint8_t ver_ :1;
    uint8_t IHL_ :1;
	uint8_t TOS_;
	uint16_t TLen_;
	uint8_t TTL_ :1;
	uint8_t P_ :1;
	uint8_t HChecksum_;
	Ip sip_;
	Ip tip_;
};
#pragma pack(pop)
