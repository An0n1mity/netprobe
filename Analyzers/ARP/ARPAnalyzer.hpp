#ifndef ARP_ANALYZER_HPP
#define ARP_ANALYZER_HPP

#include "../Analyzer.hpp"

// DHCPAnalyzer class (derived from Analyzer)
class ARPAnalyzer : public Analyzer {
private:
    std::unordered_set<pcpp::MacAddress, MacAddressHash, MacAddressEqual> senderMacs;
    std::unordered_set<pcpp::IPAddress, IPAddressHash, IPAddressEqual> senderIPs;
    std::unordered_set<pcpp::IPAddress, IPAddressHash, IPAddressEqual> targetIPs;

public:
    ARPAnalyzer(HostManager& hostManager) : Analyzer(hostManager) {}
    // Method to analyze a packet (overrides the virtual method in Analyzer)
    void analyzePacket(pcpp::Packet& parsedPacket) override;
};

#endif // DHCP_ANALYZER_HPP
