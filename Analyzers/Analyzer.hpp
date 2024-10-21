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
#include "MacAddress.h"
#include <iostream>
#include <map>
#include <string>
#include <thread>
#include <chrono>
#include <vector>
#include <arpa/inet.h>
#include <unordered_set>

struct MacAddressHash {
    std::size_t operator()(const pcpp::MacAddress& mac) const {
        // Example hash implementation based on the byte array representation of the MAC address
        return std::hash<std::string>()(mac.toString());
    }
};

// Custom equality function for pcpp::MacAddress
struct MacAddressEqual {
    bool operator()(const pcpp::MacAddress& lhs, const pcpp::MacAddress& rhs) const {
        return lhs == rhs; // Assuming operator== is defined for pcpp::MacAddress
    }
};

struct IPAddressHash {
    std::size_t operator()(const pcpp::IPAddress& ip) const {
        // Example hash implementation based on the byte array representation of the IP address
        return std::hash<std::string>()(ip.toString());
    }
};

// Custom equality function for pcpp::IPAddress
struct IPAddressEqual {
    bool operator()(const pcpp::IPAddress& lhs, const pcpp::IPAddress& rhs) const {
        return lhs == rhs; // Assuming operator== is defined for pcpp::IPAddress
    }
};

// Base Analyzer class
class Analyzer {
public:
    virtual ~Analyzer() {}
    // Virtual method to analyze specific protocol packets, to be implemented by derived classes
    virtual void analyzePacket(pcpp::Packet& packet) = 0;
};

#endif // ANALYZER_HPP
