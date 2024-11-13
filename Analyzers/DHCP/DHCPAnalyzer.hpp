#ifndef DHCP_ANALYZER_HPP
#define DHCP_ANALYZER_HPP

#include "../Analyzer.hpp"

// DHCPAnalyzer class (derived from Analyzer)
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
