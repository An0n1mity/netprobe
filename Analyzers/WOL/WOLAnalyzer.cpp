#include "WOLAnalyzer.hpp"

void WOLAnalyzer::analyzePacket(pcpp::Packet& parsedPacket) {
    // Check if the packet has Ethernet layer
    pcpp::EthLayer* ethLayer = parsedPacket.getLayerOfType<pcpp::EthLayer>();
    if (ethLayer == nullptr) {
        return; // No Ethernet layer, exit the function
    }
    // check if the packet is a WOL packet
    if (ethLayer->getEthHeader()->etherType != 0x4208) {
        return; // Not a WOL packet, exit
    }

    // Get the mac address of the source 
    pcpp::MacAddress sourceMacAddr = ethLayer->getSourceMac();

    // Get the mac address of the target in the WOL payload 
    pcpp::MacAddress targetMacAddrStr = pcpp::MacAddress(ethLayer->getLayerPayload() + 6);

    // Add the source and target mac addresses to the set
    wolSourceMacs.insert(sourceMacAddr);
    wolTargetMacs.insert(targetMacAddrStr);
}