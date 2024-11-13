#include "ARPAnalyzer.hpp"

// Method to analyze a packet (overrides the virtual method in Analyzer)
void ARPAnalyzer::analyzePacket(pcpp::Packet& parsedPacket) {
    // Extract ARP layer
    pcpp::ArpLayer* arpLayer = parsedPacket.getLayerOfType<pcpp::ArpLayer>();
    if (arpLayer == nullptr) {
        return;
    }

    // Extract ARP source
    pcpp::MacAddress srcMac = arpLayer->getSenderMacAddress();
    pcpp::IPAddress srcIp = arpLayer->getSenderIpAddr();

    // Extract ARP destination
    pcpp::IPAddress dstIp = arpLayer->getTargetIpAddr();

    pcpp::RawPacket* rawPacket = parsedPacket.getRawPacket();
    timespec ts = rawPacket->getPacketTimeStamp();

    // Check and add to the appropriate set if the IP is not already present
    if (srcMac != pcpp::MacAddress::Zero) {
        senderMacs.insert(srcMac);
    }
    
    if (!srcIp.isZero()) {
        senderIPs.insert(srcIp);
    }

    if (!dstIp.isZero()) {
        targetIPs.insert(dstIp);
    }

    // Update the host manager with the ARP data
    auto arpData = std::make_unique<ARPData>(ts, srcMac, srcIp, dstIp);
    hostManager.updateHost(ProtocolType::ARP, std::move(arpData));
}
