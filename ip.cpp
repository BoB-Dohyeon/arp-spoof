#include "ip.h"

void Ip::print(){
	printf("%d.%d.%d.%d\n", ip_[0], ip_[1], ip_[2], ip_[3]);
}

bool Ip::compare(Ip com){
	for(int i = 0; i < this->size; i++)
		if(com.ip_[i] != this->ip_[i])
			return false;
	return true;	
}

uint32_t Ip::int_8_to_32(){
	uint32_t data = 0;
	for(int i = 0; i < this->size; i++){
		data += ip_[i] << ((this->size - i - 1) * 8);
	}
	return data;
}
