#ifndef DHCP_ANALYZER_HPP
#define DHCP_ANALYZER_HPP

#include "../Analyzer.hpp"
#include <unordered_set>
#include <string>

// DHCPAnalyzer class (derived from Analyzer)
class DHCPAnalyzer : public Analyzer {
private:
    // Vector of clients IP addresses
    std::unordered_set<std::string> clientsIps;
    // Vector of DHCP server IP addresses
    std::unordered_set<std::string> dhcpServerIps;
    // Vector of gateway IP addresses
    std::unordered_set<std::string> gatewayIps;
    // Vector of DNS server IP addresses
    std::unordered_set<std::string> dnsServerIps;

public:
    // Method to analyze a packet (overrides the virtual method in Analyzer)
    void analyzePacket(pcpp::Packet& parsedPacket) override;

    // Print captured hosts
    void printHostMap();
};

#endif // DHCP_ANALYZER_HPP
