#include "LLDPAnalyzer.hpp"
#include "PcapFileDevice.h"
#include "PcapLiveDeviceList.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "UdpLayer.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <algorithm>

// LLDP TLV Types (for parsing purposes)
enum LLDPTlvType {
    LLDP_TLV_TYPE_END_OF_LLDPDU = 0,
    LLDP_TLV_TYPE_CHASSIS_ID = 1,
    LLDP_TLV_TYPE_PORT_ID = 2,
    LLDP_TLV_TYPE_TTL = 3,
    LLDP_TLV_TYPE_SYSTEM_NAME = 5,
    LLDP_TLV_TYPE_SYSTEM_DESCRIPTION = 6,
    LLDP_TLV_TYPE_SYSTEM_CAPABILITIES = 7,
    LLDP_TLV_TYPE_PORT_DESCRIPTION = 4,
    LLDP_TLV_TYPE_MANAGEMENT_ADDRESS = 8,
    LLDP_TLV_TYPE_IEEE_802_3_MAC_PHY = 127  // IEEE 802.3 MAC/PHY Extension TLV
};

// IEEE 802.3 MAC/PHY TLV subtype
enum IeeeTlvSubtype {
    IEEE_TLV_SUBTYPE_AUTONEGOTIATION = 1,  // Auto-negotiation information
    IEEE_TLV_SUBTYPE_MAXIMUM_FRAME_SIZE = 4, // Maximum Frame Size
    IEEE_TLV_SUBTYPE_LINK_AGGREGATION = 3 // Link Aggregation
};

// Helper function to convert byte array to hex string
std::string toHexString(const uint8_t* data, size_t length) {
    std::ostringstream oss;
    for (size_t i = 0; i < length; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    }
    return oss.str();
}

// Helper function to interpret system capabilities
std::string interpretSystemCapabilities(uint16_t capabilities) {
    std::ostringstream oss;
    if (capabilities & 0x0001) oss << "Other, ";
    if (capabilities & 0x0002) oss << "Repeater, ";
    if (capabilities & 0x0004) oss << "Bridge, ";
    if (capabilities & 0x0008) oss << "WLAN Access Point, ";
    if (capabilities & 0x0010) oss << "Router, ";
    if (capabilities & 0x0020) oss << "Telephone, ";
    if (capabilities & 0x0040) oss << "DOCSIS Cable Device, ";
    if (capabilities & 0x0080) oss << "Station Only, ";
    if (capabilities & 0x0100) oss << "C-VLAN Component, ";
    if (capabilities & 0x0200) oss << "S-VLAN Component, ";
    if (capabilities & 0x0400) oss << "Two-port MAC Relay, ";
    
    std::string capStr = oss.str();
    if (!capStr.empty()) {
        capStr.pop_back(); // Remove trailing space
        capStr.pop_back(); // Remove trailing comma
    }
    return capStr;
}

// Helper function to parse LLDP TLVs from the payload
std::map<std::string, std::string> parseLldpTlv(const uint8_t* payload, size_t payloadSize) {
    std::map<std::string, std::string> lldpInfo;
    size_t offset = 0;

    while (offset < payloadSize) {
        // Each TLV is structured as: Type (7 bits) | Length (9 bits) | Value (variable length)
        uint16_t tlvHeader = ntohs(*reinterpret_cast<const uint16_t*>(payload + offset));
        uint8_t tlvType = (tlvHeader >> 9) & 0x7F;  // Extract 7-bit type
        uint16_t tlvLength = tlvHeader & 0x1FF;     // Extract 9-bit length
        offset += 2;

        if (tlvLength == 0 || offset + tlvLength > payloadSize) {
            break;  // Invalid TLV length or out of bounds
        }

        const uint8_t* tlvValue = payload + offset;

        // Parse based on TLV type
        switch (tlvType) {
            case LLDP_TLV_TYPE_CHASSIS_ID:
                lldpInfo["Chassis ID"] = toHexString(tlvValue, tlvLength);
                break;
            case LLDP_TLV_TYPE_PORT_ID:
                lldpInfo["Port ID"] = std::string(reinterpret_cast<const char*>(tlvValue), tlvLength);
                break;
            case LLDP_TLV_TYPE_TTL:
                lldpInfo["TTL"] = std::to_string(ntohs(*reinterpret_cast<const uint16_t*>(tlvValue)));
                break;
            case LLDP_TLV_TYPE_SYSTEM_NAME:
                lldpInfo["System Name"] = std::string(reinterpret_cast<const char*>(tlvValue), tlvLength);
                break;
            case LLDP_TLV_TYPE_SYSTEM_DESCRIPTION:
                lldpInfo["System Description"] = std::string(reinterpret_cast<const char*>(tlvValue), tlvLength);
                break;
            case LLDP_TLV_TYPE_SYSTEM_CAPABILITIES: {
                uint16_t capabilities = ntohs(*reinterpret_cast<const uint16_t*>(tlvValue));
                uint16_t enabledCapabilities = ntohs(*reinterpret_cast<const uint16_t*>(tlvValue + 2));
                lldpInfo["System Capabilities"] = interpretSystemCapabilities(capabilities);
                lldpInfo["Enabled Capabilities"] = interpretSystemCapabilities(enabledCapabilities);
                break;
            }
            case LLDP_TLV_TYPE_PORT_DESCRIPTION:
                lldpInfo["Port Description"] = std::string(reinterpret_cast<const char*>(tlvValue), tlvLength);
                break;
            case LLDP_TLV_TYPE_MANAGEMENT_ADDRESS:
                lldpInfo["Management Address"] = toHexString(tlvValue, tlvLength);
                break;
            case LLDP_TLV_TYPE_IEEE_802_3_MAC_PHY:
                if (tlvLength >= 1) {
                    uint8_t subtype = tlvValue[0];
                    if (subtype == IEEE_TLV_SUBTYPE_AUTONEGOTIATION && tlvLength >= 6) {
                        bool autonegEnabled = tlvValue[1] & 0x80; // Autonegotiation enabled flag
                        uint16_t advertisedCapabilities = ntohs(*reinterpret_cast<const uint16_t*>(tlvValue + 4));
                        lldpInfo["Autonegotiation"] = autonegEnabled ? "Enabled" : "Disabled";
                        lldpInfo["Advertised Capabilities"] = interpretSystemCapabilities(advertisedCapabilities);
                    } else if (subtype == IEEE_TLV_SUBTYPE_MAXIMUM_FRAME_SIZE && tlvLength >= 3) {
                        uint16_t maxFrameSize = ntohs(*reinterpret_cast<const uint16_t*>(tlvValue + 1));
                        lldpInfo["Maximum Frame Size"] = std::to_string(maxFrameSize);
                    } else if (subtype == IEEE_TLV_SUBTYPE_LINK_AGGREGATION && tlvLength >= 5) {
                        bool linkAggregationEnabled = tlvValue[1] & 0x80; // Link aggregation enabled flag
                        uint8_t aggregationPortId = tlvValue[4]; // Aggregation Port ID
                        lldpInfo["Link Aggregation"] = linkAggregationEnabled ? "Enabled" : "Disabled";
                        lldpInfo["Aggregation Port ID"] = std::to_string(aggregationPortId);
                    }
                }
                break;
            case LLDP_TLV_TYPE_END_OF_LLDPDU:
                return lldpInfo;  // End of LLDPDU
            default:
                break;
        }

        offset += tlvLength;
    }

    return lldpInfo;
}

// Method to analyze a packet (overrides the virtual method in Analyzer)
void LLDPAnalyzer::analyzePacket(pcpp::Packet& parsedPacket) {
    // Check if the packet has Ethernet layer
    pcpp::EthLayer* ethLayer = parsedPacket.getLayerOfType<pcpp::EthLayer>();
    if (ethLayer == nullptr) {
        return; // No Ethernet layer, exit the function
    }

    // LLDP uses a special EtherType (0x88cc)
    uint16_t etherType = ntohs(ethLayer->getEthHeader()->etherType);
    if (etherType != 0x88CC) {
        return; // Not an LLDP packet, exit
    }

    // Extract LLDP payload (after Ethernet header)
    const uint8_t* payload = ethLayer->getLayerPayload();
    size_t payloadSize = ethLayer->getLayerPayloadSize();

    // Parse LLDP TLVs
    std::map<std::string, std::string> lldpInfo = parseLldpTlv(payload, payloadSize);

    // Extract the source MAC address of the LLDP packet
    std::string sourceMac = ethLayer->getSourceMac().toString();

    // Store the LLDP information, keyed by source MAC address
    lldpMap[sourceMac] = lldpInfo;
}

void LLDPAnalyzer::printHostMap() {
    std::cout << "Captured LLDP Information:" << std::endl;
    
    for (const auto& entry : lldpMap) {
        const std::string& macAddress = entry.first;
        const std::map<std::string, std::string>& lldpInfo = entry.second;

        std::cout << "Source MAC: " << macAddress << std::endl;
        for (const auto& info : lldpInfo) {
            std::cout << "  " << info.first << ": " << info.second << std::endl;
        }
        std::cout << std::endl;
    }
}
