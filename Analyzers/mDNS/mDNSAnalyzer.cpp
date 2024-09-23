#include "mDNSAnalyzer.hpp"

void mDNSAnalyzer::analyzePacket(pcpp::Packet& parsedPacket) {
    // Check if the packet is Ethernet, IPv4, and UDP
    pcpp::EthLayer* ethLayer = parsedPacket.getLayerOfType<pcpp::EthLayer>();
    pcpp::IPv4Layer* ipLayer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
    pcpp::UdpLayer* udpLayer = parsedPacket.getLayerOfType<pcpp::UdpLayer>();
    pcpp::DnsLayer* dnsLayer = parsedPacket.getLayerOfType<pcpp::DnsLayer>();

    if (ethLayer == NULL || ipLayer == NULL || udpLayer == NULL || dnsLayer == NULL) {
        return; // Not an Ethernet, IP, UDP, or DNS packet
    }

    // Check if the UDP packet is for mDNS (port 5353)
    uint16_t srcPort = ntohs(udpLayer->getUdpHeader()->portSrc);
    uint16_t dstPort = ntohs(udpLayer->getUdpHeader()->portDst);

    // Extract the DNS queries/responses (assuming mDNS)
    if (dnsLayer->getQueryCount() > 0) {
        // Process DNS Queries (mDNS requests)
        for (pcpp::DnsQuery* query = dnsLayer->getFirstQuery(); query != NULL; query = dnsLayer->getNextQuery(query)) {
            std::string queriedDomain = query->getName();
            std::cout << "[mDNS Query] Domain Queried: " << queriedDomain << std::endl;
        }
    }

    if (dnsLayer->getAnswerCount() > 0) {
        // Process DNS Answers (mDNS responses)
        for (pcpp::DnsResource* answer = dnsLayer->getFirstAnswer(); answer != NULL; answer = dnsLayer->getNextAnswer(answer)) {
            if (answer->getType() == pcpp::DNS_TYPE_A) {
                std::string hostname = answer->getName();
                std::string ipAddress = answer->getData()->toString();
                std::cout << "[mDNS Response] Hostname: " << hostname << " | IP: " << ipAddress << std::endl;
                
                // Store hostname to IP mapping
                hostnameMap[hostname] = ipAddress;
            }
        }
    }
}
