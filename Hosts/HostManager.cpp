#include "HostManager.hpp"

void HostManager::updateHostJson(const Host& host) {
    for (Json::ArrayIndex i = 0; i < hostsJson.size(); ++i) {
        // use boost::split to split the string into a vector of strings
        std::vector<std::string> mac_address;
        boost::split(mac_address, hostsJson[i]["MAC"].asString(), boost::is_any_of(" "));
       
        if (mac_address[0] ==  boost::to_upper_copy(host.getMACAddress().toString())) {
            // Replace the existing entry with the updated host
            hostsJson[i] = host.toJson();
            return; // Exit after updating
        }
    }

    // If the host is not found, add a new entry
    hostsJson.append(host.toJson());
}

void HostManager::updateHost(ProtocolType protocol, std::unique_ptr<ProtocolData> data) {
    timespec first_seen, last_seen;
    switch (protocol) {
        case ProtocolType::ARP: {
            ARPData* arpData = dynamic_cast<ARPData*>(data.get());
            if (arpData == nullptr) {
                return;
            }

            pcpp::MacAddress senderMac = arpData->senderMac;
            pcpp::IPAddress senderIp = arpData->senderIp;
            pcpp::IPAddress targetIp = arpData->targetIp;

            // Check if the host already exists
            if (hostMap.find(senderMac) != hostMap.end()) {
                Host& host = hostMap[senderMac];
                host.updateProtocolData(ProtocolType::ARP, std::move(data));
                if(!senderIp.isZero())
                    host.setIPAddress(senderIp);
                clock_gettime(CLOCK_REALTIME, &last_seen);
                host.setLastSeen(last_seen);

                updateHostJson(host);
            } else {
                Host host(senderMac, senderIp);
                clock_gettime(CLOCK_REALTIME, &first_seen);
                host.setFirstSeen(first_seen);
                host.setLastSeen(first_seen);
                host.updateProtocolData(ProtocolType::ARP, std::move(data));
                
                hostsJson.append(host.toJson());
                hostMap[senderMac] = std::move(host);
            }

            break;
        }
        case ProtocolType::DHCP: {
            DHCPData* dhcpData = dynamic_cast<DHCPData*>(data.get());
            if (dhcpData == nullptr) {
                return;
            }

            pcpp::MacAddress clientMac = dhcpData->clientMac;
            pcpp::IPAddress ipAddress = dhcpData->ipAddress;
            std::string hostname = dhcpData->hostname;

            // Check if the host already exists
            if (hostMap.find(clientMac) != hostMap.end()) {
                Host& host = hostMap[clientMac];
                host.updateProtocolData(ProtocolType::DHCP, std::move(data));
                if(!ipAddress.isZero())
                    host.setIPAddress(ipAddress);
                clock_gettime(CLOCK_REALTIME, &last_seen);
                host.setLastSeen(last_seen);

                updateHostJson(host);
            } else {
                Host host(clientMac, ipAddress, hostname);
                clock_gettime(CLOCK_REALTIME, &first_seen);
                host.setFirstSeen(first_seen);
                host.setLastSeen(first_seen);
                host.updateProtocolData(ProtocolType::DHCP, std::move(data));
                
                hostsJson.append(host.toJson());
                hostMap[clientMac] = std::move(host);
            }
            break;
        }
        case ProtocolType::STP: {
            STPData* stpData = dynamic_cast<STPData*>(data.get());
            if (stpData == nullptr) {
                return;
            }

            pcpp::MacAddress senderMac = stpData->senderMAC;

            // Check if the host already exists
            if (hostMap.find(senderMac) != hostMap.end()) {
                Host& host = hostMap[pcpp::MacAddress::Zero];
                host.updateProtocolData(ProtocolType::STP, std::move(data));
                clock_gettime(CLOCK_REALTIME, &last_seen);
                host.setLastSeen(last_seen);

                updateHostJson(host);
            } else {
                Host host(senderMac);
                clock_gettime(CLOCK_REALTIME, &first_seen);
                host.setFirstSeen(first_seen);
                host.setLastSeen(first_seen);
                host.updateProtocolData(ProtocolType::STP, std::move(data));
                
                hostsJson.append(host.toJson());
                hostMap[senderMac] = std::move(host);
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

void HostManager::printHostMap() {
    std::cout << hostsJson << std::endl;
    /*for (const auto& host : hostMap) {
        std::cout << host.second << std::endl;
    }*/
}