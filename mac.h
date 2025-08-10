#pragma once

#include "pch.h"

struct Mac {
public:
	static const uint8_t size = 6;
	
	Mac() {};
	
	Mac(const Mac& m){ memcpy(this->mac_, m.mac_, size); }
	
	Mac(const uint8_t* int_mac){ memcpy(this->mac_, int_mac, this->size); }

	// input 예시 : "FF:FF:FF:FF:FF:FF"
	Mac(const string string_mac) { 
		for(uint8_t i = 0; i <= 16; i+=3)
			this->mac_[i/3] = convert_char_to_int(string_mac[i]) * 16 + convert_char_to_int(string_mac[i+1]); 
	}
	
	const uint8_t* return_data() const { return mac_; }
	
	uint32_t convert_char_to_int(const char ch);
	
	void print();
	
	bool compare(Mac com);

protected:
	uint8_t mac_[size];
};