#ifndef TCP_H
#define TCP_H

#include <iostream>
#include <cstring>
#include <stdint.h>
#include <pcap.h>
#include <netinet/tcp.h>
#include "Ip.hpp"
#include "NetworkUtilities.hpp"
using namespace std;

struct tcph_pseudo {
	uint32_t ip_src;
	uint32_t ip_dst;
	uint8_t zero;
	uint8_t protocol;
	uint16_t length;
};

struct tcp_checksum {
	struct tcph_pseudo pseudo;
	tcphdr _tcphdr;
};

/*!
 * \class Tcp
 * \brief Class header for build Tcp packet.
 */
class Tcp : public Ip {
	public:
	/*!
	 * \brief Tcp Constructor.
	 Tcp class's constructor.
	 * \param Pointer to network interface.
	 */
	Tcp(pcap_t *device);
	/*!
	 * \brief Tcp Destructor.
	 Tcp class's Destructor.
	 */
	~Tcp();
	/*!
	 * \brief Function for send packet.
	 * \return Status (if trame is sended or not).
	 */
	virtual int send();
	/*!
	 * \brief Accessor for set source port.
	 * \param Source port.
	 */
	void setSource(int port);
	/*!
	 * \brief Accessor for set destination port.
	 * \param Destination port.
	 */
	void setDest(int port);

	/*!
	 * \brief Accessor for set TCP sequence.
	 * \param TCP sequence.
	 */
	void setSeq(unsigned long seq);

	protected:
	struct tcphdr *_tcp;
	struct tcp_checksum *_tcph;
};

#endif
