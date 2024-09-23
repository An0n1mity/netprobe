#ifndef ANALYZER_HPP
#define ANALYZER_HPP

#include "PcapLiveDeviceList.h"
#include "PcapLiveDevice.h"
#include "Packet.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "UdpLayer.h"
#include "DhcpLayer.h"
#include "DnsLayer.h"
#include "DnsResourceData.h"
#include "TcpLayer.h"
#include <iostream>
#include <map>
#include <string>
#include <thread>
#include <chrono>
#include <vector>
#include <arpa/inet.h>


// Base Analyzer class
class Analyzer {
public:
    virtual ~Analyzer() {}
    // Virtual method to analyze specific protocol packets, to be implemented by derived classes
    virtual void analyzePacket(pcpp::Packet& packet) = 0;
};

#endif // ANALYZER_HPP
