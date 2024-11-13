#ifndef CDP_ANALYZER_H
#define CDP_ANALYZER_H

#include "PcapFileDevice.h"
#include "../Analyzer.hpp"
#include "PcapLiveDeviceList.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include <string>

// CDP TLV Types (for parsing purposes)
enum CDPTlvType {
    CDP_TLV_TYPE_DEVICE_ID = 0x0001, //Validé
    CDP_TLV_TYPE_ADDRESS = 0x0002, //Validé
    CDP_TLV_TYPE_PORT_ID = 0x0003, //Validé
    CDP_TLV_TYPE_CAPABILITIES = 0x0004, //Validé
    CDP_TLV_TYPE_SOFTWARE_VERSION = 0x0005, //Validé
    CDP_TLV_TYPE_PLATFORM = 0x0006, //Validé
    CDP_TLV_TYPE_IP_PREFIX = 0x0007, //A vérifier s'il s'agit du bon TLV
    CDP_TLV_TYPE_NATIVE_VLAN = 0x000A, //Validé
    CDP_TLV_TYPE_MGMT_ADDRESS = 0x0016, //A vérifier s'il s'agit du bon TLV
    CDP_TLV_TYPE_DUPLEX = 0x000B, //Validé
    CDP_TLV_TYPE_TRUST_BITMAP = 0x0012, //Validé
    CDP_TLV_TYPE_UNTRUSTED_PORT_COS = 0x0013, //Validé
    CDP_TLV_TYPE_SYSTEM_NAME = 0x000D, //A vérifier s'il s'agit du bon TLV
    CDP_TLV_TYPE_SYSTEM_DESCRIPTION = 0x000E,  //A vérifier s'il s'agit du bon TLV
    CDP_TLV_TYPE_POWER_CONSUMPTION = 0x0010, //Validé
    CDP_TLV_TYPE_POWER_REQUEST = 0x000F
};

class CDPAnalyzer : public Analyzer {
public:
    CDPAnalyzer(HostManager& hostManager) : Analyzer(hostManager) {}
    void analyzePacket(pcpp::Packet& parsedPacket) override;
    void printHostMap();  // Afficher les informations sur les hôtes CDP
    //std::string convertToIpAddress(const std::string& hexData);

private:
    // Variables pour stocker toutes les informations TLV possibles
    std::string deviceID;
    std::string portID;
    std::string address;
    std::string softwareVersion;
    std::string platform;
    uint32_t capabilities;
    uint16_t nativeVlan;
    std::string mgmtAddress;
    std::string systemName;
    std::string systemDescription;
    uint16_t duplex;
    uint16_t powerConsumption;
    uint16_t powerRequest;

    // Méthodes pour vérifier et analyser un paquet CDP
    bool isCdpPacket(const uint8_t* rawData, size_t rawDataLen);
    void analyzeCdpPayload(const uint8_t* payload, size_t payloadSize);

    // Méthodes pour extraire des informations à partir des TLV
    void extractDeviceID(const uint8_t* tlvValue, size_t tlvLength);
    void extractPortID(const uint8_t* tlvValue, size_t tlvLength);
    void extractAddress(const uint8_t* tlvValue, size_t tlvLength);
    void extractCapabilities(const uint8_t* tlvValue, size_t tlvLength);
    void extractSoftwareVersion(const uint8_t* tlvValue, size_t tlvLength);
    void extractPlatform(const uint8_t* tlvValue, size_t tlvLength);
    void extractNativeVlan(const uint8_t* tlvValue, size_t tlvLength);
    void extractMgmtAddress(const uint8_t* tlvValue, size_t tlvLength);
    void extractDuplex(const uint8_t* tlvValue, size_t tlvLength);
    void extractSystemName(const uint8_t* tlvValue, size_t tlvLength);
    void extractSystemDescription(const uint8_t* tlvValue, size_t tlvLength);
    void extractPowerConsumption(const uint8_t* tlvValue, size_t tlvLength);
    void extractPowerRequest(const uint8_t* tlvValue, size_t tlvLength);

    // Utilitaires
    std::string toHexString(const uint8_t* data, size_t length);
    std::string convertToIpAddress(const std::string& hexData);
    std::string parseCapabilities(uint32_t capabilities);
};

#endif // CDP_ANALYZER_H
