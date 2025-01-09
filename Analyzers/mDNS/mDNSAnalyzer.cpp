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

    if (srcPort != 5353 && dstPort != 5353) {
        return; // Not an mDNS packet
    }

    pcpp::MacAddress srcMac = ethLayer->getSourceMac();
    std::string queriedDomain, hostname, ipAddress;

    // Extract the DNS queries/responses (assuming mDNS)
    if (dnsLayer->getQueryCount() > 0) {
        // Process DNS Queries (mDNS requests)
        for (pcpp::DnsQuery* query = dnsLayer->getFirstQuery(); query != NULL; query = dnsLayer->getNextQuery(query)) {
            queriedDomain = query->getName();
        }   
    }

    if (dnsLayer->getAnswerCount() > 0) {
        // Process DNS Answers (mDNS responses)
        for (pcpp::DnsResource* answer = dnsLayer->getFirstAnswer(); answer != NULL; answer = dnsLayer->getNextAnswer(answer)) {
            if (answer->getType() == pcpp::DNS_TYPE_A) {
                hostname = answer->getName();
                ipAddress = answer->getData()->toString();
                // edit the protcol data with the response 
            }
        }
    }

    pcpp::RawPacket* rawPacket = parsedPacket.getRawPacket();
    timespec ts = rawPacket->getPacketTimeStamp();  

    // Update the host manager with the mDNS data
    auto mdnsData = std::make_unique<mDNSData>(ts, queriedDomain, srcMac, hostname, ipAddress);
    
    #ifdef DEBUG
    std::cout << "mDNS Data:" << std::endl;
    std::cout << "\tQueried Domain: " << mdnsData->queriedDomain << std::endl;
    std::cout << "\tClient MAC: " << mdnsData->clientMac << std::endl;
    std::cout << "\tHostname: " << mdnsData->hostname << std::endl;
    std::cout << "\tIP Address: " << mdnsData->ipAddress << std::endl;
    #endif

    hostManager.updateHost(ProtocolType::MDNS, std::move(mdnsData));
}
