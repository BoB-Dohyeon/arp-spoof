#include "mac.h"

void Mac::print() {
	printf("%02x:%02x:%02x:%02x:%02x:%02x\n", mac_[0], mac_[1], mac_[2], mac_[3], mac_[4], mac_[5]);
}

uint32_t Mac::convert_char_to_int(const char ch) {
	if('0' <= ch && ch <= '9') return (uint32_t)ch - '0';
	else if('a' <= ch && ch <= 'z') return (uint32_t)ch - 'a' + 10;
	else if('A' <= ch && ch <= 'Z') return (uint32_t)ch - 'A' + 10;
	else return -1;
}

bool Mac::compare(Mac com){
	for(int i = 0; i < this->size; i++)
		if(com.mac_[i] != this->mac_[i])
			return false;
	return true;
}
