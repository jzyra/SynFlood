CXX=g++
CXXFLAGS=-W -Wall
LDFLAGS=-lpcap
EXEC=arppoisonning

all: $(EXEC)

arppoisonning: Arp.o SynFlood.o Ethernet.o NetworkUtilities.o Packet.o Ip.o Tcp.o
	$(CXX) -o synflood Arp.o SynFlood.o Ethernet.o NetworkUtilities.o Packet.o Ip.o Tcp.o main.cpp $(LDFLAGS)

Arp.o: Arp.cpp
	$(CXX) -o Arp.o -c Arp.cpp $(CXXFLAGS) $(LDFLAGS)

SynFlood.o: SynFlood.cpp
	$(CXX) -o SynFlood.o -c SynFlood.cpp $(CXXFLAGS) $(LDFLAGS)

Ethernet.o: Ethernet.cpp
	$(CXX) -o Ethernet.o -c Ethernet.cpp $(CXXFLAGS) $(LDFLAGS)

NetworkUtilities.o: NetworkUtilities.cpp
	$(CXX) -o NetworkUtilities.o -c NetworkUtilities.cpp $(CXXFLAGS) $(LDFLAGS)

Packet.o: Packet.cpp
	$(CXX) -o Packet.o -c Packet.cpp $(CXXFLAGS) $(LDFLAGS)

Ip.o: Ip.cpp
	$(CXX) -o Ip.o -c Ip.cpp $(CXXFLAGS) $(LDFLAGS)

Tcp.o: Tcp.cpp
	$(CXX) -o Tcp.o -c Tcp.cpp $(CXXFLAGS) $(LDFLAGS)

clean:
	rm -rf *.o

mrproper: clean
	rm -rf $(EXEC)
