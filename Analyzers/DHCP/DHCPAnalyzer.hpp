#ifndef DHCP_ANALYZER_HPP
#define DHCP_ANALYZER_HPP

#include "../Analyzer.hpp"

// DHCPAnalyzer class (derived from Analyzer)
/**
 * @class DHCPAnalyzer
 * @brief Analyzes DHCP packets and updates the host manager.
 * 
 * The DHCPAnalyzer class is responsible for analyzing DHCP packets and updating the host manager
 * with the DHCP data. It extracts the client MAC address, client IP address, DHCP server IP address,
 * gateway IP address, and DNS server IP address from the DHCP packet and updates the host manager with
 * this information.
 * 
 * The DHCPAnalyzer class maintains sets of client MAC addresses, client IP addresses, DHCP server IP addresses,
 * gateway IP addresses, and DNS server IP addresses to keep track of unique addresses seen in the network.
 * 
 * The DHCPAnalyzer class overrides the analyzePacket method from the base Analyzer class to handle DHCP packets.
 * 
 */
class DHCPAnalyzer : public Analyzer {
private:
    std::unordered_set<pcpp::MacAddress, MacAddressHash, MacAddressEqual> clientsMacs;
    std::unordered_set<pcpp::IPAddress, IPAddressHash, IPAddressEqual> clientsIps;
    std::unordered_set<pcpp::IPAddress, IPAddressHash, IPAddressEqual> dhcpServerIps;
    std::unordered_set<pcpp::IPAddress, IPAddressHash, IPAddressEqual> gatewayIps;
    std::unordered_set<pcpp::IPAddress, IPAddressHash, IPAddressEqual> dnsServerIps;

public:
    DHCPAnalyzer(HostManager& hostManager) : Analyzer(hostManager) {}

    // Method to analyze a packet (overrides the virtual method in Analyzer)
    void analyzePacket(pcpp::Packet& parsedPacket) override;
    std::unordered_set<pcpp::MacAddress, MacAddressHash, MacAddressEqual> getClientsMacs() const { return clientsMacs; }
    std::unordered_set<pcpp::IPAddress, IPAddressHash, IPAddressEqual> getClientsIps() const { return clientsIps; }
    std::unordered_set<pcpp::IPAddress, IPAddressHash, IPAddressEqual> getDhcpServerIps() const { return dhcpServerIps; }
    std::unordered_set<pcpp::IPAddress, IPAddressHash, IPAddressEqual> getGatewayIps() const { return gatewayIps; }
    std::unordered_set<pcpp::IPAddress, IPAddressHash, IPAddressEqual> getDnsServerIps() const { return dnsServerIps; }
};

#endif // DHCP_ANALYZER_HPP
