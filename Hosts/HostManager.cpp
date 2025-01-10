#include "HostManager.hpp"
#include <boost/algorithm/string.hpp>
#include <ctime>
#include <fstream>
#include <iostream>

void HostManager::updateHostJson(const Host& host) {
    for (Json::ArrayIndex i = 0; i < hostsJson.size(); ++i) {
        std::vector<std::string> mac_address;
        boost::split(mac_address, hostsJson[i]["MAC"].asString(), boost::is_any_of(" "));

        if (mac_address[0] == boost::to_upper_copy(host.getMACAddress().toString())) {
            hostsJson[i] = host.toJson();
            return;
        }
    }
    hostsJson.append(host.toJson());
}

void HostManager::updateHost(ProtocolType protocol, std::unique_ptr<ProtocolData> data) {
    timespec first_seen, last_seen;

    auto processHost = [&](pcpp::MacAddress mac, pcpp::IPAddress ip, const std::string& hostname, ProtocolType type) {
        if (hostMap.find(mac) != hostMap.end()) {
            Host& host = hostMap[mac];
            host.updateProtocolData(type, std::move(data));
            if (!ip.isZero()) host.setIPAddress(ip);
            clock_gettime(CLOCK_REALTIME, &last_seen);
            host.setLastSeen(last_seen);
            updateHostJson(host);
        } else {
            Host host(mac, ip, hostname);
            clock_gettime(CLOCK_REALTIME, &first_seen);
            host.setFirstSeen(first_seen);
            host.setLastSeen(first_seen);
            host.updateProtocolData(type, std::move(data));
            hostsJson.append(host.toJson());
            hostMap[mac] = std::move(host);
        }
    };

    switch (protocol) {
        case ProtocolType::ARP: {
            ARPData* arpData = dynamic_cast<ARPData*>(data.get());
            if (arpData) {
                processHost(arpData->senderMac, arpData->senderIp, "", ProtocolType::ARP);
            }
            break;
        }
        case ProtocolType::DHCP: {
            DHCPData* dhcpData = dynamic_cast<DHCPData*>(data.get());
            if (dhcpData) {
                processHost(dhcpData->clientMac, dhcpData->ipAddress, dhcpData->hostname, ProtocolType::DHCP);
            }
            break;
        }
        case ProtocolType::STP: {
            STPData* stpData = dynamic_cast<STPData*>(data.get());
            if (stpData) {
                processHost(stpData->senderMAC, pcpp::IPv4Address::Zero, "", ProtocolType::STP);
            }
            break;
        }
        case ProtocolType::LLDP: {
            LLDPData* lldpData = dynamic_cast<LLDPData*>(data.get());
            if (lldpData) {
                processHost(lldpData->senderMAC, pcpp::IPv4Address::Zero, lldpData->systemName, ProtocolType::LLDP);
            }
            break;
        }
        case ProtocolType::SSDP: {
            SSDPData* ssdpData = dynamic_cast<SSDPData*>(data.get());
            if (ssdpData) {
                processHost(ssdpData->senderMAC, pcpp::IPv4Address::Zero, "", ProtocolType::SSDP);
            }
            break;
        }
        case ProtocolType::CDP: {
            CDPData* cdpData = dynamic_cast<CDPData*>(data.get());
            if (cdpData) {
                processHost(cdpData->senderMAC, cdpData->senderIP, "", ProtocolType::CDP);
            }
            break;
        }
        case ProtocolType::WOL: {
            WOLData* wolData = dynamic_cast<WOLData*>(data.get());
            if (wolData) {
                processHost(wolData->senderMAC, pcpp::IPv4Address::Zero, "", ProtocolType::WOL);
            }
            break;
        }
    }
}

void HostManager::dumpHostsToFile(const std::string& filename) {
    std::ofstream file(filename);
    if (!file.is_open()) {
        std::cerr << "Error opening file!" << std::endl;
        return;
    }

    file << hostsJson;
    file.close();
}

const Json::Value& HostManager::getHostsJson() const {
    return hostsJson;
}

void HostManager::printHostMap() {
    std::cout << hostsJson << std::endl;
}
