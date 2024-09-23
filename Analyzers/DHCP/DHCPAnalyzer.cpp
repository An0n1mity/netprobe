#include "DHCPAnalyzer.hpp"

// Helper function to extract option data as a string (IP address or text)
std::string getDhcpOptionAsString(pcpp::DhcpLayer* dhcpLayer, pcpp::DhcpOptionTypes optionType, const std::string& defaultValue = "Not Assigned") {
    pcpp::DhcpOption option = dhcpLayer->getOptionData(optionType);
    if (!option.isNull()) {
        if (option.getType() == pcpp::DhcpOptionTypes::DHCPOPT_DHCP_REQUESTED_ADDRESS || 
            option.getType() == pcpp::DhcpOptionTypes::DHCPOPT_DHCP_SERVER_IDENTIFIER ||
            option.getType() == pcpp::DhcpOptionTypes::DHCPOPT_ROUTERS ||
            option.getType() == pcpp::DhcpOptionTypes::DHCPOPT_DOMAIN_NAME_SERVERS) {
            return option.getValueAsIpAddr().toString();
        }
        return std::string(reinterpret_cast<const char*>(option.getValue()), option.getDataSize());
    }
    return defaultValue;
}

void DHCPAnalyzer::analyzePacket(pcpp::Packet& parsedPacket) {

    auto* dhcpLayer = parsedPacket.getLayerOfType<pcpp::DhcpLayer>();

    if (!dhcpLayer) {
        return; // Not an Ethernet, IPv4, UDP, or DHCP packet
    }

    // Extract DHCP information using helper function
    std::string ipAddress = getDhcpOptionAsString(dhcpLayer, pcpp::DHCPOPT_DHCP_REQUESTED_ADDRESS);
    std::string hostname = getDhcpOptionAsString(dhcpLayer, pcpp::DHCPOPT_HOST_NAME);
    std::string dhcpServerIp = getDhcpOptionAsString(dhcpLayer, pcpp::DHCPOPT_DHCP_SERVER_IDENTIFIER);
    std::string gatewayIp = getDhcpOptionAsString(dhcpLayer, pcpp::DHCPOPT_ROUTERS);
    std::string dnsServerIp = getDhcpOptionAsString(dhcpLayer, pcpp::DHCPOPT_DOMAIN_NAME_SERVERS);

    // Check and add to the appropriate set if the IP is not already present
    if (ipAddress != "Not Assigned") {
        clientsIps.insert(ipAddress);
    }

    if (dhcpServerIp != "Not Assigned") {
        dhcpServerIps.insert(dhcpServerIp);
    }

    if (gatewayIp != "Not Assigned") {
        gatewayIps.insert(gatewayIp);
    }

    if (dnsServerIp != "Not Assigned") {
        dnsServerIps.insert(dnsServerIp);
    }
}

// Print captured DHCP clients
void DHCPAnalyzer::printHostMap() {
    std::cout << "Captured DHCP Clients:" << std::endl;
    for (const auto& ip : clientsIps) {
        std::cout << ip << std::endl;
    }
    std::cout << std::endl;

    std::cout << "Captured DHCP Servers:" << std::endl;
    for (const auto& ip : dhcpServerIps) {
        std::cout << ip << std::endl;
    }

    std::cout << "Captured Gateways:" << std::endl;
    for (const auto& ip : gatewayIps) {
        std::cout << ip << std::endl;
    }

    std::cout << "Captured DNS Servers:" << std::endl;
    for (const auto& ip : dnsServerIps) {
        std::cout << ip << std::endl;
    }
}
