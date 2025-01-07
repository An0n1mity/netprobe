#include "SSDPAnalyzer.hpp"
#include "PcapFileDevice.h"
#include "PcapLiveDeviceList.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "UdpLayer.h"
#include <sstream>
#include <algorithm>

// Helper function to parse SSDP headers
std::map<std::string, std::string> parseSsdpHeaders(const std::string& ssdpPayload) {
    std::map<std::string, std::string> headers;
    std::istringstream stream(ssdpPayload);
    std::string line;

    // Skip the request line (e.g., NOTIFY * HTTP/1.1 or M-SEARCH * HTTP/1.1)
    std::getline(stream, line);

    // Parse headers
    while (std::getline(stream, line) && !line.empty()) {
        std::string::size_type delimiterPos = line.find(": ");
        if (delimiterPos != std::string::npos) {
            std::string headerName = line.substr(0, delimiterPos);
            std::string headerValue = line.substr(delimiterPos + 2);
            headers[headerName] = headerValue;
        }
    }

    return headers;
}

// Method to analyze a packet (overrides the virtual method in Analyzer)
void SSDPAnalyzer::analyzePacket(pcpp::Packet& parsedPacket) {
    // Check if the packet has UDP layer
    pcpp::UdpLayer* udpLayer = parsedPacket.getLayerOfType<pcpp::UdpLayer>();
    if (udpLayer == nullptr) {
        return; // No UDP layer, exit the function
    }

    // SSDP typically uses UDP port 1900
    uint16_t dstPort = ntohs(udpLayer->getUdpHeader()->portDst);
    uint16_t srcPort = ntohs(udpLayer->getUdpHeader()->portSrc);
    if (dstPort != 1900 && srcPort != 1900) {
        return; // Not SSDP, exit
    }

    // Extract UDP payload (SSDP message)
    size_t payloadSize = udpLayer->getLayerPayloadSize();
    const uint8_t* payload = udpLayer->getLayerPayload();

    // Ensure payload is valid and not empty
    if (payload == nullptr || payloadSize == 0) {
        return; // No payload found, exit the function
    }

    SSDPLayer ssdpLayer(payload, payloadSize);
    //std::cout << ssdpLayer << std::endl;

    // Extract IP address of the sender (source IP)
    pcpp::IPv4Layer* ipLayer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
    if (ipLayer != nullptr) {
        clientIP = ipLayer->getSrcIPAddress().toString();
    }

    // Extract MAC address of the sender (source MAC)
    pcpp::EthLayer* ethLayer = parsedPacket.getLayerOfType<pcpp::EthLayer>();
    if (ethLayer != nullptr) {
        clientMAC = ethLayer->getSourceMac().toString();
    }

    auto ssdpData = std::make_unique<SSDPData>(parsedPacket.getRawPacket()->getPacketTimeStamp(), pcpp::MacAddress(clientMAC), pcpp::IPv4Address(clientIP), ssdpLayer.getSSDPType(), ssdpLayer.getSSDPHeaders());
    hostManager.updateHost(ProtocolType::SSDP, std::move(ssdpData));
    
}

void SSDPAnalyzer::printHostMap() {
    std::cout << "Captured SSDP Information:" << std::endl;

    // Remove trailing spaces or newlines for NOTIFY info
    server.erase(std::remove_if(server.begin(), server.end(), ::isspace), server.end());
    location.erase(std::remove_if(location.begin(), location.end(), ::isspace), location.end());

    std::cout << "Server: " << server << " | Location: " << location << std::endl;

    // Print M-SEARCH specific info
    std::cout << "M-SEARCH Client IP: " << clientIP << " | Client MAC: " << clientMAC << std::endl;
}
