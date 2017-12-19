/*!
 * \file Ip.cpp
 * \brief Class for build IP packet.
 * \author Jeremy ZYRA
 * \version 1.0
 */
#include "Ip.hpp"

Ip::Ip(pcap_t *device) : Ethernet(device) {
	//Init srand
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC,&ts);
	srand(ts.tv_nsec);
	_ip = new iphdr;
	_ip->ihl = 0x05;	
	_ip->version = 0x04;	
	_ip->tos = 0x010;	
	_ip->tot_len = htons(sizeof(struct iphdr)+sizeof(ether_header));
	_ip->id = 0x00;
	_ip->frag_off = htons(0x4000);
	_ip->ttl = 0xFF;
	//0x06 pour TCP.
	_ip->protocol = 0x00;
	_ip->check = 0x00;
	_ip->saddr = 0x00;
	_ip->daddr = 0x00;
	_ethernet->ether_type = 0x008;
}

Ip::~Ip() {
	delete _ip;
}

void Ip::setSaddr(u_int32_t ip) {
	_ip->saddr = ip;
}

void Ip::setDaddr(u_int32_t ip) {
	_ip->daddr = ip;
}

void Ip::setProtocol(u_int8_t protocol) {
	_ip->protocol = protocol;
}

void Ip::setId(unsigned short id) {
	_ip->id = id; 
}

u_int32_t Ip::getSaddr() {
	return _ip->saddr;
}

u_int32_t Ip::getDaddr() {
	return _ip->daddr;
}

u_int8_t Ip::getProtocol() {
	return _ip->protocol;
}

int Ip::send() {
	//_ip->check = checksum((unsigned short *)_ip);
	u_char trame[sizeof(ether_header) + sizeof(iphdr)];
	//Copy ethernet and IP header in trame to send.
	memcpy(trame, _ethernet, sizeof(ether_header));
	memcpy(trame + sizeof(ether_header), _ip, sizeof(iphdr));
	//Send packet.
	return pcap_sendpacket(_device, (u_char *)trame, sizeof(ether_header) + sizeof(iphdr));
}
