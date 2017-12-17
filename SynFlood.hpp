/*!
 * \file SynFlood.hpp
 * \brief Class header for run MITM attack.
 * \author Jeremy ZYRA
 * \version 1.0
 */
#ifndef ARPSPOOFING_H
#define ARPSPOOFING_H

#include <iostream>
#include <cstdlib>
#include <pcap.h>
#include <stdint.h>
#include <arpa/inet.h>
#include "Arp.hpp"
#include "Tcp.hpp"
#include "NetworkUtilities.hpp"

#define PACKET_SIZE 65536
#define TIMEOUT_MS 3000
#define PROMISC_MODE 0
using namespace std;

/*!
 * \class SynFlood
 * \brief Class header for run MITM attack.
 */
class SynFlood {
	public:
	/*!
	 * \brief SynFlood Constructor.
	 SynFlood class's constructor.
	 * \param iface : Pointer to network interface.
	 * \param target : Target's IP.
	 * \param port : Target port.
	 * \param verbose : Verbose mode.
	 */
	SynFlood(char *iface, char *target, int port, bool verbose);
	/*!
	 * \brief Run SYN flood attack.
	 */
	void run();

	private:
	/*!
	 * \brief Get MAC address of the target.
	 */
	ucharMac *getTargetMac();

	int _port;
	pcap_t *_iface;
	uint8Ip _targetIp;
	uint8Ip _deviceIp;
	ucharMac _deviceMac;
	bool _verbose;
};

#endif
