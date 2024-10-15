#include "LLDPAnalyzer.hpp"
#include "PcapFileDevice.h"
#include "PcapLiveDeviceList.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "UdpLayer.h"


// Method to analyze a packet (overrides the virtual method in Analyzer)
void LLDPAnalyzer::analyzePacket(pcpp::Packet& parsedPacket) {
    // Check if the packet has Ethernet layer
    pcpp::EthLayer* ethLayer = parsedPacket.getLayerOfType<pcpp::EthLayer>();
    if (ethLayer == nullptr) {
        return; // No Ethernet layer, exit the function
    }

    // check if the packet is an LLDP packet
    if (ethLayer->getEthHeader()->etherType != 0xcc88) {
        return; // Not an LLDP packet, exit
    }

    // LLDP uses a special EtherType (0x88cc)
    LLDPLayer lldpLayer(ethLayer->getLayerPayload(), ethLayer->getLayerPayloadSize());
    
    // Print the LLDP information
    std::cout << lldpLayer << std::endl;

}
