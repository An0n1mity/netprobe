#include "DHCPAnalyzer.hpp"

// Helper function to extract option data as a string (IP address or text)
pcpp::IPAddress getDhcpOption(pcpp::DhcpLayer* dhcpLayer, pcpp::DhcpOptionTypes optionType, const std::string& defaultValue = "Not Assigned") {
    pcpp::DhcpOption option = dhcpLayer->getOptionData(optionType);
    if (!option.isNull()) {
        if (option.getType() == pcpp::DhcpOptionTypes::DHCPOPT_DHCP_REQUESTED_ADDRESS || 
            option.getType() == pcpp::DhcpOptionTypes::DHCPOPT_DHCP_SERVER_IDENTIFIER ||
            option.getType() == pcpp::DhcpOptionTypes::DHCPOPT_ROUTERS ||
            option.getType() == pcpp::DhcpOptionTypes::DHCPOPT_DOMAIN_NAME_SERVERS) {
            return option.getValueAsIpAddr();
        }
    }
    return pcpp::IPv4Address::Zero;
}

void DHCPAnalyzer::analyzePacket(pcpp::Packet& parsedPacket) {

    auto* dhcpLayer = parsedPacket.getLayerOfType<pcpp::DhcpLayer>();

    if (!dhcpLayer) {
        return; // Not an Ethernet, IPv4, UDP, or DHCP packet
    }

    // Extract DHCP information using helper function
    pcpp::MacAddress clientMac = dhcpLayer->getClientHardwareAddress();
    pcpp::IPAddress ipAddress =  getDhcpOption(dhcpLayer, pcpp::DHCPOPT_DHCP_REQUESTED_ADDRESS);
    pcpp::IPAddress hostname = getDhcpOption(dhcpLayer, pcpp::DHCPOPT_HOST_NAME);
    pcpp::IPAddress dhcpServerIp = getDhcpOption(dhcpLayer, pcpp::DHCPOPT_DHCP_SERVER_IDENTIFIER);
    pcpp::IPAddress gatewayIp = getDhcpOption(dhcpLayer, pcpp::DHCPOPT_ROUTERS);
    pcpp::IPAddress dnsServerIp = getDhcpOption(dhcpLayer, pcpp::DHCPOPT_DOMAIN_NAME_SERVERS);
    
    pcpp::RawPacket* rawPacket = parsedPacket.getRawPacket();
    timespec ts = rawPacket->getPacketTimeStamp();

    // Update the host manager with the DHCP data
    auto dhcpData = std::make_unique<DHCPData>(ts, clientMac, ipAddress, "", dhcpServerIp, gatewayIp, dnsServerIp);
    hostManager.updateHost(ProtocolType::DHCP, std::move(dhcpData));
}
