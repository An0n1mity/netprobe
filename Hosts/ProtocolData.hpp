#ifndef PROTOCOL_DATA_HPP
#define PROTOCOL_DATA_HPP

#include "MacAddress.h"
#include "IPv4Layer.h"
#include "../Layers/STP/STPLayer.hpp"
#include <string>
#include <ctime>

enum class ProtocolType {
    DHCP,
    MDNS,
    ARP,
    SSDP,
    LLDP,
    CDP,
    STP,
    WOL
};

// Base class for protocol data
struct ProtocolData {
    ProtocolType protocol;
    timespec timestamp;
     ProtocolData(ProtocolType proto, timespec ts = {}) 
        : protocol(proto), timestamp(ts) {}
    virtual ~ProtocolData() = default;
    virtual ProtocolType getProtocolType() const {
        return protocol;
    }
};

// Data structure for DHCP protocol
struct DHCPData : public ProtocolData {
    pcpp::MacAddress clientMac;
    pcpp::IPAddress ipAddress;
    std::string hostname;
    pcpp::IPAddress dhcpServerIp;
    pcpp::IPAddress gatewayIp;
    pcpp::IPAddress dnsServerIp;

     // Constructor
    DHCPData(timespec ts, pcpp::MacAddress mac, pcpp::IPAddress ip, const std::string& host,
             pcpp::IPAddress dhcpServer, pcpp::IPAddress gateway, pcpp::IPAddress dns)
        : ProtocolData(ProtocolType::DHCP, ts), clientMac(mac), ipAddress(ip),
          hostname(host), dhcpServerIp(dhcpServer), gatewayIp(gateway), dnsServerIp(dns) {}
};

// Data structure for mDNS protocol
struct mDNSData : public ProtocolData {
    std::string queriedDomain;
    pcpp::MacAddress clientMac;
    std::string hostname;
    pcpp::IPAddress ipAddress;

    // Constructor
    mDNSData(timespec ts, const std::string& domain, pcpp::MacAddress mac, const std::string& host, pcpp::IPAddress ip)
        : ProtocolData(ProtocolType::MDNS, ts), queriedDomain(domain), clientMac(mac), hostname(host), ipAddress(ip) { }
};

// Data structure for ARP protocol
struct ARPData : public ProtocolData {
    pcpp::MacAddress senderMac;
    pcpp::IPAddress senderIp;
    pcpp::IPAddress targetIp;

    // Constructor
    ARPData(timespec ts, pcpp::MacAddress mac, pcpp::IPAddress sender, pcpp::IPAddress target)
        : ProtocolData(ProtocolType::ARP, ts), senderMac(mac), senderIp(sender), targetIp(target) {}
};

// Data structure for STP protocol
struct STPData : public ProtocolData {
    pcpp::MacAddress senderMAC;
    STPLayer::RootIdentifier rootIdentifier;
    STPLayer::BridgeIdentifier bridgeIdentifier;

    // Modified constructor to take an STPLayer object directly
    STPData(timespec ts, pcpp::MacAddress mac, STPLayer::RootIdentifier rootId, STPLayer::BridgeIdentifier bridgeId)
        : ProtocolData(ProtocolType::STP, ts),
            senderMAC(mac),  // Initialize from parameter
            rootIdentifier(rootId),  // Initialize from parameter
            bridgeIdentifier(bridgeId) {}  // Initialize from parameter
};

struct ProtocolDataComparator {
    bool operator()(const std::unique_ptr<ProtocolData>& lhs, const std::unique_ptr<ProtocolData>& rhs) const {
        if (!lhs || !rhs) return false;

        // Compare by protocol type first
        if (lhs->getProtocolType() != rhs->getProtocolType()) {
            return lhs->getProtocolType() < rhs->getProtocolType();
        }

        // Cast and compare by specific protocol data fields, ignoring timestamp
        if (lhs->getProtocolType() == ProtocolType::DHCP) {
            const DHCPData* lhsData = static_cast<const DHCPData*>(lhs.get());
            const DHCPData* rhsData = static_cast<const DHCPData*>(rhs.get());
            return lhsData->clientMac != rhsData->clientMac || lhsData->ipAddress != rhsData->ipAddress || lhsData->hostname != rhsData->hostname ||
                   lhsData->dhcpServerIp != rhsData->dhcpServerIp || lhsData->gatewayIp != rhsData->gatewayIp || lhsData->dnsServerIp != rhsData->dnsServerIp;
        }

        if (lhs->getProtocolType() == ProtocolType::MDNS) {
            const mDNSData* lhsData = static_cast<const mDNSData*>(lhs.get());
            const mDNSData* rhsData = static_cast<const mDNSData*>(rhs.get());
            return lhsData->queriedDomain != rhsData->queriedDomain || lhsData->clientMac != rhsData->clientMac || lhsData->hostname != rhsData->hostname || lhsData->ipAddress != rhsData->ipAddress;
        }

        if (lhs->getProtocolType() == ProtocolType::ARP) {
            const ARPData* lhsData = static_cast<const ARPData*>(lhs.get());
            const ARPData* rhsData = static_cast<const ARPData*>(rhs.get());
            return lhsData->senderMac != rhsData->senderMac || lhsData->senderIp != rhsData->senderIp || lhsData->targetIp != rhsData->targetIp;
        }

        if (lhs->getProtocolType() == ProtocolType::STP) {
            const STPData* lhsData = static_cast<const STPData*>(lhs.get());
            const STPData* rhsData = static_cast<const STPData*>(rhs.get());
            return lhsData->senderMAC != rhsData->senderMAC || lhsData->rootIdentifier.priority != rhsData->rootIdentifier.priority ||
                   lhsData->rootIdentifier.systemIDExtension != rhsData->rootIdentifier.systemIDExtension || lhsData->rootIdentifier.systemID != rhsData->rootIdentifier.systemID ||
                   lhsData->bridgeIdentifier.priority != rhsData->bridgeIdentifier.priority || lhsData->bridgeIdentifier.systemIDExtension != rhsData->bridgeIdentifier.systemIDExtension ||
                   lhsData->bridgeIdentifier.systemID != rhsData->bridgeIdentifier.systemID;
        }

        return false; // Fallback case
    }
};

// Add other protocol data structures as needed...

#endif // PROTOCOL_DATA_HPP