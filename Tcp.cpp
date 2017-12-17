/*!
 * \file Tcp.cpp
 * \brief Class for build TCP packet.
 * \author Jeremy ZYRA
 * \version 1.0
 */
#include "Tcp.hpp"

Tcp::Tcp(pcap_t *device) : Ip(device) {
	//Init srand
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	srand(ts.tv_nsec);
	_tcp = new tcphdr;
	_tcph = new tcp_checksum;
	_tcp->source = htons(0x32b4);
	_tcp->dest = htons(0x50);
	_tcp->seq = htonl(0x00);
	_tcp->ack_seq = 0x00;
	_tcp->doff = 0x5;
	_tcp->th_x2 = 0x5;
	_tcp->ack = 0;
	_tcp->syn = 1;
	_tcp->fin = 0;
	_tcp->res1 = 0;
	_tcp->urg = 0;
	_tcp->psh = 0;
	_tcp->rst = 0;
	_tcp->res2 = 0;
	_tcp->window = htons(0x1000);
	_tcp->check = 0x00;
	_tcp->urg_ptr = 0;
	_ip->protocol = 0x06;
	_ip->tot_len = htons(40);
}

void Tcp::setSource(int port) {
	_tcp->source = htons(port);
}

void Tcp::setDest(int port) {
	_tcp->dest = htons(port);
}

void Tcp::setSeq(unsigned long seq) {
	_tcp->seq = seq;
}

int Tcp::send() {
	_ip->check = NetworkUtilities::checksum((unsigned short *)_ip, sizeof(iphdr));
	_tcph->pseudo.ip_src = _ip->saddr;
	_tcph->pseudo.ip_dst = _ip->daddr;
	_tcph->pseudo.zero = 0x00;
	_tcph->pseudo.protocol = _ip->protocol;
	_tcph->pseudo.length = htons(sizeof(tcphdr));
	_tcph->_tcphdr = *_tcp;
	_tcp->check = 0x00;
	_tcp->check = NetworkUtilities::checksum((unsigned short *)_tcph, sizeof(tcp_checksum));
	u_char trame[sizeof(ether_header) + sizeof(iphdr) + sizeof(tcphdr)];
	memcpy(trame, _ethernet, sizeof(ether_header));
	memcpy(trame + sizeof(ether_header), _ip, sizeof(iphdr));
	memcpy(trame + sizeof(ether_header) + sizeof(iphdr), _tcp, sizeof(tcphdr));
	//Send packet.
	return pcap_sendpacket(_device, (u_char *)trame, sizeof(ether_header) + sizeof(iphdr) + sizeof(tcphdr));
}
