#ifndef ARP_ANALYZER_HPP
#define ARP_ANALYZER_HPP

#include "../Analyzer.hpp"
#include <map>
#include <string>
#include <unordered_set>


// DHCPAnalyzer class (derived from Analyzer)
class ARPAnalyzer : public Analyzer {
private:
    std::map<std::string, std::string> hostMap; // Store MAC to IP address mapping
    std::unordered_set<std::string> destinationIps; // Store destination IPs

public:
    // Method to analyze a packet (overrides the virtual method in Analyzer)
    void analyzePacket(pcpp::Packet& parsedPacket) override;

    // Print captured hosts
    void printHostMap();
};

#endif // DHCP_ANALYZER_HPP
