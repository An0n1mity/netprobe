#ifndef HOST_HPP
#define HOST_HPP

#include "MacAddress.h"
#include "IPv4Layer.h"
#include "ProtocolData.hpp"

#include <string>
#include <unordered_map>
#include <ctime>
#include <iostream>
#include <array>
#include <set>
#include <jsoncpp/json/json.h>

class Host {
  public:
    Host() : ip_address(pcpp::IPv4Address::Zero), mac_address(pcpp::MacAddress::Zero), host_name("") {}
    Host(const pcpp::IPAddress& ip, const pcpp::MacAddress& mac, const std::string& hostname = "", const timespec& first = timespec(), const timespec& last = timespec())
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
    void updateProtocolData(ProtocolType protocol, std::unique_ptr<ProtocolData> data);
    // Date to string
    std::string dateToString(const timespec& ts) const {
        char buffer[80];
        struct tm t;
        localtime_r(&ts.tv_sec, &t);
        strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &t);
        return std::string(buffer);
    }

    // Overload the << operator to print the host information
    friend std::ostream& operator<<(std::ostream& os, const Host& host) {
        os << "IP Address: " << host.ip_address << std::endl;
        os << "MAC Address: " << host.mac_address << std::endl;
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