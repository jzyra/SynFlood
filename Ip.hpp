#ifndef IP_H
#define IP_H

#include <iostream>
#include <cstring>
#include <stdint.h>
#include <pcap.h>
#include <netinet/ip.h>
#include "Ethernet.hpp"
using namespace std;

/*!
 * \class Ip
 * \brief Class header for build Ip packet.
 */
class Ip : public Ethernet {
	public:
	/*!
	 * \brief Ip Constructor.
	 Ip class's constructor.
	 * \param Pointer to network interface.
	 */
	Ip(pcap_t *device);
	/*!
	 * \brief Function for send packet.
	 * \return Status (if trame is sended or not).
	 */
	virtual int send();
	/*!
	 * \brief Accessor for set source ip address.
	 * \param IP address.
	 */
	void setSaddr(u_int32_t ip);
	/*!
	 * \brief Accessor for set destination ip address.
	 * \param IP address.
	 */
	void setDaddr(u_int32_t ip);
	/*!
	 * \brief Accessor for set protocol.
	 * \param protocol.
	 */
	void setProtocol(u_int8_t protocol);
	/*!
	 * \brief Accessor for set ID.
	 * \param IP ID.
	 */
	void setId(unsigned short id);
	/*!
	 * \brief Accessor for get source ip address.
	 * \return IP address.
	 */
	u_int32_t getSaddr();
	/*!
	 * \brief Accessor for get destination ip address.
	 * \return IP address.
	 */
	u_int32_t getDaddr();
	/*!
	 * \brief Accessor for get protocol.
	 * \return protocol.
	 */
	u_int8_t getProtocol();

	protected:
	struct iphdr *_ip;
};

#endif
