#include "ARPAnalyzer.hpp"

// Method to analyze a packet (overrides the virtual method in Analyzer)
void ARPAnalyzer::analyzePacket(pcpp::Packet& parsedPacket) {
    // Extract ARP layer
    pcpp::ArpLayer* arpLayer = parsedPacket.getLayerOfType<pcpp::ArpLayer>();
    if (arpLayer == nullptr) {
        return;
    }

    // Extract ARP source
    std::string srcMac = arpLayer->getSenderMacAddress().toString();
    std::string srcIp = arpLayer->getSenderIpAddr().toString();

    // Extract ARP destination
    std::string dstIp = arpLayer->getTargetIpAddr().toString();

    // Display the extracted information
    std::cout << "[ARP] Source MAC: " << srcMac << " | Source IP: " << srcIp << std::endl;

    // Add source MAC to IP mapping to hostMap
    hostMap[srcMac] = srcIp;

    // Add destination IP to destinationIps
    destinationIps.insert(dstIp);
}

void ARPAnalyzer::printHostMap() {
    std::cout << "Captured Hosts:" << std::endl;
    for (const auto& entry : hostMap) {
        std::cout << "MAC: " << entry.first << " | IP: " << entry.second << std::endl;
    }
    std::cout << std::endl;

    std::cout << "Captured Destination IPs:" << std::endl;
    for (const auto& ip : destinationIps) {
        std::cout << ip << std::endl;
    }
    std::cout << std::endl;
}
