#ifndef HOST_HPP
#define HOST_HPP

#include "MacAddress.h"
#include "IPv4Layer.h"
#include "ProtocolData.hpp"

#include <string>
#include <unordered_map>
#include <ctime>
#include <iostream>
#include <fstream>
#include <array>
#include <set>
#include <json/json.h>
#include <boost/algorithm/string.hpp>

void loadVendorDatabase(const std::string& filename, std::map<std::string, std::string>& vendorDatabase);
void swapMacBytes(std::string& mac);
std::string getVendorName(const std::string& macPrefix);
std::string pcppMACAddressToString(const pcpp::MacAddress& mac, const std::map<std::string, std::string>& vendorDatabase);

extern std::map<std::string, std::string> vendorDatabase;

class Host {
  public:
    Host() : mac_address(pcpp::MacAddress::Zero), ip_address(pcpp::IPv4Address::Zero), host_name("") {}
    Host(const pcpp::MacAddress& mac, const pcpp::IPAddress& ip = pcpp::IPv4Address::Zero, const std::string& hostname = "", const timespec& first = timespec(), const timespec& last = timespec())
      : ip_address(ip), mac_address(mac), host_name(hostname), first_seen(first), last_seen(last) {}

    // Move constructor
    Host(Host&& other) noexcept
        : ip_address(std::move(other.ip_address)),
          mac_address(std::move(other.mac_address)),
          host_name(std::move(other.host_name)),
          first_seen(other.first_seen),
          last_seen(other.last_seen),
          protocols_data(std::move(other.protocols_data)) {}

    // Move assignment operator
    Host& operator=(Host&& other) noexcept {
        if (this != &other) {
            ip_address = std::move(other.ip_address);
            mac_address = std::move(other.mac_address);
            host_name = std::move(other.host_name);
            first_seen = other.first_seen;
            last_seen = other.last_seen;
            protocols_data = std::move(other.protocols_data);
        }
        return *this;
    }

    // Getters
    pcpp::IPAddress getIPAddress() const { return ip_address; }
    pcpp::MacAddress getMACAddress() const { return mac_address; }
    std::string getHostName() const { return host_name; }
    timespec getFirstSeen() const { return first_seen; }
    timespec getLastSeen() const { return last_seen; }

    // Setters                  
    void setIPAddress(const pcpp::IPAddress& ip) { ip_address = ip; }
    void setMACAddress(const pcpp::MacAddress& mac) { mac_address = mac; }
    void setHostName(const std::string& hostname) { host_name = hostname; }
    void setFirstSeen(const timespec& first) { first_seen = first; }
    void setLastSeen(const timespec& last) { last_seen = last; }
    void getProtocolData(ProtocolType protocol, ProtocolData& data) const;
    void updateProtocolData(ProtocolType protocol, std::unique_ptr<ProtocolData> data);
    void editProtocolData(ProtocolType protocol, std::unique_ptr<ProtocolData> prev_data, std::unique_ptr<ProtocolData> new_data);

    // Date to string
    std::string dateToString(const timespec& ts) const {
        char buffer[80];
        struct tm t;
        localtime_r(&ts.tv_sec, &t);
        strftime(buffer, sizeof(buffer), "%d-%m-%Y %H:%M:%S", &t);
        return std::string(buffer);
    }
    

    Json::Value toJson() const {
        Json::Value hostJson;
        hostJson["MAC"] = pcppMACAddressToString(mac_address, vendorDatabase);
        hostJson["IP"] = ip_address.toString();
        hostJson["HOSTNAME"] = host_name;
        hostJson["FIRST SEEN"] = dateToString(first_seen);
        hostJson["LAST SEEN"] = dateToString(last_seen);

        Json::Value protocolsJson;
        for (const auto& protocolDataVector : protocols_data) {
            for (const auto& protocolDataPtr : protocolDataVector) {
                if (!protocolDataPtr) {
                    continue; // Skip uninitialized or empty protocol data slots
                }
                ProtocolData* protocol_data = protocolDataPtr.get();
                if (protocol_data->protocol == ProtocolType::DHCP) {
                    DHCPData* dhcp_data = static_cast<DHCPData*>(protocol_data);
                    Json::Value dhcpJson;
                    dhcpJson["TIMESTAMP"] = dateToString(dhcp_data->timestamp);
                    dhcpJson["CLIENT MAC"] = dhcp_data->clientMac.toString();
                    dhcpJson["IP"] = dhcp_data->ipAddress.toString();
                    dhcpJson["HOSTNAME"] = dhcp_data->hostname;
                    dhcpJson["DHCP SERVER IP"] = dhcp_data->dhcpServerIp.toString();
                    dhcpJson["GATEWAY IP"] = dhcp_data->gatewayIp.toString();
                    dhcpJson["DNS SERVER IP"] = dhcp_data->dnsServerIp.toString();
                    protocolsJson["DHCP"].append(dhcpJson);
                }
                else if (protocol_data->protocol == ProtocolType::ARP) {
                    ARPData* arp_data = static_cast<ARPData*>(protocol_data);
                    Json::Value arpJson;
                    arpJson["TIMESTAMP"] = dateToString(arp_data->timestamp);
                    arpJson["SENDER MAC"] = arp_data->senderMac.toString();
                    arpJson["SENDER IP"] = arp_data->senderIp.toString();
                    arpJson["TARGET IP"] = arp_data->targetIp.toString();
                    protocolsJson["ARP"].append(arpJson);
                }
                else if (protocol_data->protocol == ProtocolType::STP) {
                    STPData* stp_data = static_cast<STPData*>(protocol_data);
                    Json::Value stpJson;
                    stpJson["TIMESTAMP"] = dateToString(stp_data->timestamp);
                    stpJson["SENDER MAC"] = stp_data->senderMAC.toString();
                    uint16_t reversedRootIdentifier = reverseBytes16(stp_data->rootIdentifier.priority);
                    stpJson["ROOT IDENTIFIER"]["PRIORITY"] = reversedRootIdentifier;
                    stpJson["ROOT IDENTIFIER"]["SYSTEM ID EXTENSION"] = stp_data->rootIdentifier.systemIDExtension;
                    uint64_t reversedRootSystemID = reverseBytes48(stp_data->rootIdentifier.systemID);
                    stpJson["ROOT IDENTIFIER"]["SYSTEM ID"] = pcpp::MacAddress(reinterpret_cast<uint8_t*>(&reversedRootSystemID)).toString();
                    uint16_t reversedBridgeIdentifier = reverseBytes16(stp_data->bridgeIdentifier.priority);
                    stpJson["BRIDGE IDENTIFIER"]["PRIORITY"] = reversedBridgeIdentifier;
                    stpJson["BRIDGE IDENTIFIER"]["SYSTEM ID EXTENSION"] = stp_data->bridgeIdentifier.systemIDExtension;
                    uint64_t reversedBridgeSystemID = reverseBytes48(stp_data->bridgeIdentifier.systemID);
                    stpJson["BRIDGE IDENTIFIER"]["SYSTEM ID"] = pcpp::MacAddress(reinterpret_cast<uint8_t*>(&reversedBridgeSystemID)).toString();
                    protocolsJson["STP"].append(stpJson);
                }
            }
        }

        hostJson["PROTOCOLS"] = protocolsJson;

        return hostJson;
    }

    // Overload the << operator to print the host information
    friend std::ostream& operator<<(std::ostream& os, const Host& host) {
        os << "IP Address: " << host.ip_address << std::endl;
        os << "MAC Address: " << pcppMACAddressToString(host.mac_address, vendorDatabase) << std::endl;
        os << "Host Name: " << host.host_name << std::endl;
        os << "First Seen: " << host.dateToString(host.first_seen) << std::endl;
        os << "Last Seen: " << host.dateToString(host.last_seen) << std::endl;
        
        // Print the protocols data
        for (const auto& protocolDataVector : host.protocols_data) {
            for (const auto& protocolDataPtr : protocolDataVector) {
                if (!protocolDataPtr) {
                    continue; // Skip uninitialized or empty protocol data slots
                }   
                ProtocolData* protocol_data = protocolDataPtr.get();
                if (protocol_data->protocol == ProtocolType::DHCP) {
                    DHCPData* dhcp_data = static_cast<DHCPData*>(protocol_data);
                    os << "DHCP Data:" << std::endl;
                    os << "\tTimestamp: " << host.dateToString(dhcp_data->timestamp) << std::endl;
                    os << "\tClient MAC: " << dhcp_data->clientMac << std::endl;
                    os << "\tIP Address: " << dhcp_data->ipAddress << std::endl;
                    os << "\tHostname: " << dhcp_data->hostname << std::endl;
                    os << "\tDHCP Server IP: " << dhcp_data->dhcpServerIp << std::endl;
                    os << "\tGateway IP: " << dhcp_data->gatewayIp << std::endl;
                    os << "\tDNS Server IP: " << dhcp_data->dnsServerIp << std::endl;
                }
                else if (protocol_data->protocol == ProtocolType::ARP) {
                    ARPData* arp_data = static_cast<ARPData*>(protocol_data);
                    os << "ARP Data:" << std::endl;
                    os << "\tTimestamp: " << host.dateToString(arp_data->timestamp) << std::endl;
                    os << "\tSender MAC: " << arp_data->senderMac << std::endl;
                    os << "\tSender IP: " << arp_data->senderIp << std::endl;
                    os << "\target IP: " << arp_data->targetIp << std::endl;
                }
                else if (protocol_data->protocol == ProtocolType::STP) {
                    STPData* stp_data = static_cast<STPData*>(protocol_data);
                    os << "STP Data:" << std::endl;
                    os << "\tTimestamp: " << host.dateToString(stp_data->timestamp) << std::endl;
                    os << "\tRoot Identifier:" << std::endl;
                    uint16_t reversedRootIdentifier = reverseBytes16(stp_data->rootIdentifier.priority);
                    os << "\t\tPriority: " << std::dec << reversedRootIdentifier << std::endl;
                    os << "\t\tSystem ID Extension: " << std::dec << int(stp_data->rootIdentifier.systemIDExtension) << std::endl;
                    uint64_t reversedSystemID = reverseBytes48(stp_data->rootIdentifier.systemID);
                    // Only print the 6 bytes first of the system ID
                    os << "\t\tSystem ID: " << std::hex << std::setfill('0');
                    os << std::setw(2) << ((reversedSystemID >> 40) & 0xFF) << ":";
                    os << std::setw(2) << ((reversedSystemID >> 32) & 0xFF) << ":";
                    os << std::setw(2) << ((reversedSystemID >> 24) & 0xFF) << ":";
                    os << std::setw(2) << ((reversedSystemID >> 16) & 0xFF) << ":";
                    os << std::setw(2) << ((reversedSystemID >> 8) & 0xFF) << ":";
                    os << std::setw(2) << (reversedSystemID & 0xFF) << std::endl;

                    os << "\tBridge Identifier:" << std::endl;
                    uint16_t reversedBridgeIdentifier = reverseBytes16(stp_data->bridgeIdentifier.priority);
                    os << "\t\tPriority: " << std::dec << reversedBridgeIdentifier << std::endl;
                    os << "\t\tSystem ID Extension: " << std::dec << int(stp_data->bridgeIdentifier.systemIDExtension) << std::endl;
                    uint64_t reversedBridgeSystemID = reverseBytes48(stp_data->bridgeIdentifier.systemID);
                    // Only print the 6 bytes first of the system ID
                    os << "\t\tSystem ID: " << std::hex << std::setfill('0');
                    os << std::setw(2) << ((reversedBridgeSystemID >> 40) & 0xFF) << ":";
                    os << std::setw(2) << ((reversedBridgeSystemID >> 32) & 0xFF) << ":";
                    os << std::setw(2) << ((reversedBridgeSystemID >> 24) & 0xFF) << ":";
                    os << std::setw(2) << ((reversedBridgeSystemID >> 16) & 0xFF) << ":";
                    os << std::setw(2) << ((reversedBridgeSystemID >> 8) & 0xFF) << ":";
                    os << std::setw(2) << (reversedBridgeSystemID & 0xFF) << std::endl;
                }
            }
        }
        return os;
    }

  private:
    pcpp::IPAddress ip_address;
    pcpp::MacAddress mac_address;
    std::string host_name;
    // First time seen
    timespec first_seen;
    // Last time seen
    timespec last_seen;
    // Array to store the protocols infos 
    std::array<std::set<std::unique_ptr<ProtocolData>, ProtocolDataComparator>, 8> protocols_data;

    // Delete copy constructor and copy assignment operator
    Host(const Host&) = delete;
    Host& operator=(const Host&) = delete;
};                                                                                                                                    

#endif // HOST_HPP