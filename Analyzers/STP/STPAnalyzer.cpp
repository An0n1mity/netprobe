#include "STPAnalyzer.hpp"
#include "PcapFileDevice.h"
#include "PcapLiveDeviceList.h"
#include "EthDot3Layer.h"
#include "IPv4Layer.h"
#include "UdpLayer.h"


// Method to analyze a packet (overrides the virtual method in Analyzer)
void STPAnalyzer::analyzePacket(pcpp::Packet& parsedPacket) {
    // Check if the packet has Ethernet layer
    pcpp::EthDot3Layer* ethLayer = parsedPacket.getLayerOfType<pcpp::EthDot3Layer>();
    if (ethLayer == nullptr) {
        return; // No Ethernet layer, exit the function
    }

    const uint8_t* payload = ethLayer->getLayerPayload();
    const uint32_t logicalLinkControl = (payload[0] << 16 | payload[1] << 8 | payload[2]);
    const uint16_t protocolID = logicalLinkControl >> 8;

    if (protocolID != 0x4242) {
        return; // Not an STP packet, exit
    }

    STPLayer stplayer(payload + 6, ethLayer->getLayerPayloadSize() - 6);
    
    // Print the STP layer
    std::cout << stplayer << std::endl;
}