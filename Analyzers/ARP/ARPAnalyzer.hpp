#ifndef ARP_ANALYZER_HPP
#define ARP_ANALYZER_HPP

#include "../Analyzer.hpp"

// DHCPAnalyzer class (derived from Analyzer)
/**
 * @class ARPAnalyzer
 * @brief Analyzes ARP packets and updates the host manager.
 * 
 * The ARPAnalyzer class is responsible for analyzing ARP packets and updating the host manager
 * with the ARP data. It extracts the sender MAC address, sender IP address, and target IP address
 * from the ARP packet and updates the host manager with this information.
 * 
 * The ARPAnalyzer class maintains sets of sender MAC addresses, sender IP addresses, and target IP addresses
 * to keep track of unique addresses seen in the network.
 * 
 * The ARPAnalyzer class overrides the analyzePacket method from the base Analyzer class to handle ARP packets.
 */
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
