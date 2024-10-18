#include "CDPAnalyzer.hpp"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <pcap.h>
#include <cstring>
#include <arpa/inet.h>

const uint8_t CDP_MULTICAST_ADDR[6] = {0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc};

// Méthode pour analyser un paquet CDP
void CDPAnalyzer::analyzePacket(pcpp::Packet& parsedPacket) {
    const uint8_t* rawData = parsedPacket.getRawPacket()->getRawData();
    size_t rawDataLen = parsedPacket.getRawPacket()->getRawDataLen();

    if (!isCdpPacket(rawData, rawDataLen)) {
        return;
    }

    size_t ethHeaderLen = 22;  
    size_t cdpOffset = ethHeaderLen;

    if (cdpOffset < rawDataLen) {
        analyzeCdpPayload(rawData + cdpOffset, rawDataLen - cdpOffset);
    }
}

// Méthode pour vérifier si c'est un paquet CDP
bool CDPAnalyzer::isCdpPacket(const uint8_t* rawData, size_t rawDataLen) {
    if (rawDataLen < 22) {
        return false;
    }

    if (memcmp(rawData, CDP_MULTICAST_ADDR, 6) == 0) {
        return true;
    }

    return false;
}

// Méthode pour analyser le payload CDP et extraire les TLV
void CDPAnalyzer::analyzeCdpPayload(const uint8_t* payload, size_t payloadSize) {
    const size_t cdpHeaderSize = 4;  // Version, TTL, Checksum
    if (payloadSize < cdpHeaderSize) {
        std::cerr << "Payload too small to contain a valid CDP header" << std::endl;
        return;
    }

    size_t offset = cdpHeaderSize;

    // Boucle de traitement des TLV
    while (offset + 4 <= payloadSize) {
        uint16_t tlvType = (payload[offset] << 8) | payload[offset + 1];
        uint16_t tlvLength = (payload[offset + 2] << 8) | payload[offset + 3];

        if (tlvLength < 4 || offset + tlvLength > payloadSize) {
            std::cerr << "Invalid TLV length at offset: " << offset << std::endl;
            break;
        }

        const uint8_t* tlvValue = payload + offset + 4;
        size_t tlvValueLength = tlvLength - 4;

        // Appel des fonctions spécifiques selon le type de TLV
        switch (tlvType) {
            case CDP_TLV_TYPE_DEVICE_ID:
                extractDeviceID(tlvValue, tlvValueLength);
                break;
            case CDP_TLV_TYPE_PORT_ID:
                extractPortID(tlvValue, tlvValueLength);
                break;
            case CDP_TLV_TYPE_ADDRESS:
                extractAddress(tlvValue, tlvValueLength);
                break;
            case CDP_TLV_TYPE_CAPABILITIES:
                extractCapabilities(tlvValue, tlvValueLength);
                break;
            case CDP_TLV_TYPE_SOFTWARE_VERSION:
                extractSoftwareVersion(tlvValue, tlvValueLength);
                break;
            case CDP_TLV_TYPE_PLATFORM:
                extractPlatform(tlvValue, tlvValueLength);
                break;
            case CDP_TLV_TYPE_NATIVE_VLAN:
                extractNativeVlan(tlvValue, tlvValueLength);
                break;
            case CDP_TLV_TYPE_MGMT_ADDRESS:
                extractMgmtAddress(tlvValue, tlvValueLength);
                break;
            case CDP_TLV_TYPE_DUPLEX:
                extractDuplex(tlvValue, tlvValueLength);
                break;
            case CDP_TLV_TYPE_SYSTEM_NAME:
                extractSystemName(tlvValue, tlvValueLength);
                break;
            case CDP_TLV_TYPE_SYSTEM_DESCRIPTION:
                extractSystemDescription(tlvValue, tlvValueLength);
                break;
            case CDP_TLV_TYPE_POWER_CONSUMPTION:
                extractPowerConsumption(tlvValue, tlvValueLength);
                break;
            case CDP_TLV_TYPE_POWER_REQUEST:
                extractPowerRequest(tlvValue, tlvValueLength);
                break;
            default:
                std::cerr << "Unknown TLV type: " << tlvType << std::endl;
                break;
        }

        offset += tlvLength;
    }
}

// Méthode pour extraire l'ID de l'appareil (Device ID)
void CDPAnalyzer::extractDeviceID(const uint8_t* tlvValue, size_t tlvLength) {
    deviceID = std::string(reinterpret_cast<const char*>(tlvValue), tlvLength);
    //std::cout << "Device ID: " << deviceID << std::endl; // Debug
}

// Méthode pour extraire l'ID du port (Port ID)
void CDPAnalyzer::extractPortID(const uint8_t* tlvValue, size_t tlvLength) {
    portID = std::string(reinterpret_cast<const char*>(tlvValue), tlvLength);
    //std::cout << "Port ID: " << portID << std::endl; // Debug
}

// Méthode pour extraire l'adresse (Address)
void CDPAnalyzer::extractAddress(const uint8_t* tlvValue, size_t tlvLength) {
    if (tlvLength > 4) {
        // On ne garde que les 4 derniers octets (reste pas utile)
        tlvValue += (tlvLength - 4);  // Décale le pointeur pour ne prendre que les 8 derniers octets
        tlvLength = 4;  // Réduit la longueur à 4 octets
    }

    address = toHexString(tlvValue, tlvLength);
    //std::cout << "Address: " << address << std::endl; // Debug
}

// Méthode pour extraire les capacités (Capabilities)
void CDPAnalyzer::extractCapabilities(const uint8_t* tlvValue, size_t tlvLength) {
    if (tlvLength == 4) {
        capabilities = (tlvValue[0] << 24) | (tlvValue[1] << 16) | (tlvValue[2] << 8) | tlvValue[3];
        //std::cout << "Capabilities: " << parseCapabilities(capabilities) << std::endl; // Debug
    }
}

// Méthode pour extraire la version logicielle (Software Version)
void CDPAnalyzer::extractSoftwareVersion(const uint8_t* tlvValue, size_t tlvLength) {
    softwareVersion = std::string(reinterpret_cast<const char*>(tlvValue), tlvLength);
    //std::cout << "Software Version: " << softwareVersion << std::endl; // Debug
}

// Méthode pour extraire la plateforme (Platform)
void CDPAnalyzer::extractPlatform(const uint8_t* tlvValue, size_t tlvLength) {
    platform = std::string(reinterpret_cast<const char*>(tlvValue), tlvLength);
    //std::cout << "Platform: " << platform << std::endl; // Debug
}

// Méthode pour extraire le VLAN natif (Native VLAN)
void CDPAnalyzer::extractNativeVlan(const uint8_t* tlvValue, size_t tlvLength) {
    if (tlvLength == 2) {
        nativeVlan = (tlvValue[0] << 8) | tlvValue[1];
        //std::cout << "Native VLAN: " << nativeVlan << std::endl; // Debug
    }
}

// Méthode pour extraire l'adresse de gestion (Management Address)
void CDPAnalyzer::extractMgmtAddress(const uint8_t* tlvValue, size_t tlvLength) {
    if (tlvLength > 4) {
        // On ne garde que les 4 derniers octets (reste pas utile)
        tlvValue += (tlvLength - 4);  // Décale le pointeur pour ne prendre que les 8 derniers octets
        tlvLength = 4;  // Réduit la longueur à 4 octets
    }

    mgmtAddress = toHexString(tlvValue, tlvLength);
    //std::cout << "Management Address: " << mgmtAddress << std::endl; // Debug
}

// Méthode pour extraire le duplex (Duplex)
void CDPAnalyzer::extractDuplex(const uint8_t* tlvValue, size_t tlvLength) {
    if (tlvLength == 1) {
        duplex = tlvValue[0];
        //std::cout << "Duplex: " << (duplex == 0x01 ? "Full Duplex" : "Half Duplex") << std::endl; // Debug
    }
}

// Méthode pour extraire le nom du système (System Name)
void CDPAnalyzer::extractSystemName(const uint8_t* tlvValue, size_t tlvLength) {
    systemName = std::string(reinterpret_cast<const char*>(tlvValue), tlvLength);
    //std::cout << "System Name: " << systemName << std::endl; // Debug
}

// Méthode pour extraire la description du système (System Description)
void CDPAnalyzer::extractSystemDescription(const uint8_t* tlvValue, size_t tlvLength) {
    systemDescription = std::string(reinterpret_cast<const char*>(tlvValue), tlvLength);
    //std::cout << "System Description: " << systemDescription << std::endl; // Debug
}

// Méthode pour extraire la consommation d'énergie (Power Consumption)
void CDPAnalyzer::extractPowerConsumption(const uint8_t* tlvValue, size_t tlvLength) {
    if (tlvLength == 2) {
        powerConsumption = (tlvValue[0] << 8) | tlvValue[1];
        //std::cout << "Power Consumption: " << powerConsumption << " Watts" << std::endl; // Debug
    }
}

// Méthode pour extraire la requête d'énergie (Power Request)
void CDPAnalyzer::extractPowerRequest(const uint8_t* tlvValue, size_t tlvLength) {
    if (tlvLength == 2) {
        powerRequest = (tlvValue[0] << 8) | tlvValue[1];
        //std::cout << "Power Request: " << powerRequest << " Watts" << std::endl; // Debug
    }
}
// Conversion des IP en hexa au format texte
std::string CDPAnalyzer::convertToIpAddress(const std::string& hexData) {
    if (hexData.size() != 8) {
        return "Invalid IP";  // Vérifie que la longueur est correcte pour une adresse IPv4
    }

    uint32_t ipAddr;
    std::stringstream ss;
    ss << std::hex << hexData;
    ss >> ipAddr;

    ipAddr = ntohl(ipAddr);  // Convertit l'ordre des octets en format réseau

    struct in_addr ipStruct;
    ipStruct.s_addr = ipAddr;

    return inet_ntoa(ipStruct);  // Retourne l'adresse IP au format texte
}

// Méthode pour afficher les informations des hôtes CDP
void CDPAnalyzer::printHostMap() {
    std::cout << "CDP Host Information:" << std::endl;

    if (deviceID.empty()) {
        std::cout << "No CDP data available!" << std::endl;
        return;
    }

    std::cout << "Device ID: " << deviceID << std::endl;

    if (!portID.empty()) {
        std::cout << "Port ID: " << portID << std::endl;
    }

    if (!address.empty()) {
        std::string ipAddress = convertToIpAddress(address);
        std::cout << "Address (IPv4 only !): " << ipAddress << std::endl;
    }

    if (capabilities != 0) {
        std::cout << "Capabilities: " << parseCapabilities(capabilities) << std::endl;
    }

    if (!softwareVersion.empty()) {
        std::cout << "Software Version: " << softwareVersion << std::endl;
    }

    if (!platform.empty()) {
        std::cout << "Platform: " << platform << std::endl;
    }

    if (nativeVlan != 0) {
        std::cout << "Native VLAN: " << nativeVlan << std::endl;
    }

    if (!mgmtAddress.empty()) {
        std::string mgmtIpAddress = convertToIpAddress(mgmtAddress);
        std::cout << "Management Address (IPv4 only !): " << mgmtIpAddress << std::endl;
        std::cout << "Management Address (hex): " << mgmtAddress << std::endl;
    }

    if (duplex != 0) {
        std::cout << "Duplex: " << (duplex == 0x01 ? "Full Duplex" : "Half Duplex") << std::endl;
    }

    if (!systemName.empty()) {
        std::cout << "System Name: " << systemName << std::endl;
    }

    if (!systemDescription.empty()) {
        std::cout << "System Description: " << systemDescription << std::endl;
    }

    if (powerConsumption != 0) {
        std::cout << "Power Consumption: " << powerConsumption << " Watts" << std::endl;
    }

    if (powerRequest != 0) {
        std::cout << "Power Request: " << powerRequest << " Watts" << std::endl;
    }
}

// Convertir les données en chaîne hexadécimale
std::string CDPAnalyzer::toHexString(const uint8_t* data, size_t length) {
    std::ostringstream oss;
    for (size_t i = 0; i < length; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    }
    return oss.str();
}



// Analyser les capacités CDP
std::string CDPAnalyzer::parseCapabilities(uint32_t capabilities) {
    std::ostringstream oss;
    if (capabilities & 0x01) oss << "Router ";
    if (capabilities & 0x02) oss << "Trans-Bridge ";
    if (capabilities & 0x04) oss << "Source-Route-Bridge ";
    if (capabilities & 0x08) oss << "Switch ";
    if (capabilities & 0x10) oss << "Host ";
    if (capabilities & 0x20) oss << "IGMP ";
    if (capabilities & 0x40) oss << "Repeater ";
    return oss.str();
}
