#include "HostManager.hpp"

/**
 * @brief Updates the JSON representation of a host in the hostsJson array.
 *
 * This function searches for a host in the hostsJson array by comparing the MAC address.
 * If the host is found, it updates the existing JSON entry with the new host data.
 * If the host is not found, it appends a new JSON entry for the host.
 *
 * @param host The Host object containing the updated host information.
 */
void HostManager::updateHostJson(const Host& host) {
    // Try to find the host in the JSON array
    for (Json::ArrayIndex i = 0; i < hostsJson.size(); ++i) {
        // use boost::split to split the string into a vector of strings
        std::vector<std::string> mac_address;
        boost::split(mac_address, hostsJson[i]["MAC"].asString(), boost::is_any_of(" "));
       
        // Check if the MAC address matches
        if (mac_address[0] ==  boost::to_upper_copy(host.getMACAddress().toString())) {
            // Replace the existing entry with the updated host
            hostsJson[i] = host.toJson();
            return; // Exit after updating
        }
    }

    // If the host is not found, add a new entry
    hostsJson.append(host.toJson());
}

/**
 * @brief Updates the host information based on the provided protocol data.
 *
 * This function updates the host information in the hostMap based on the protocol type and data provided.
 * It handles three types of protocols: ARP, DHCP, and STP. For each protocol, it checks if the host already
 * exists in the hostMap. If it does, it updates the existing host's information. If it doesn't, it creates
 * a new host entry and updates the hostsJson.
 *
 * @param protocol The protocol type (ARP, DHCP, STP).
 * @param data A unique pointer to the protocol data.
 */
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

/**
 * @brief Dumps the hosts information to a specified file in JSON format.
 *
 * This function opens the specified file and writes the hosts information
 * in JSON format to it. If the file cannot be opened, an error message
 * is printed to the standard error output.
 *
 * @param filename The name of the file to which the hosts information will be written.
 */
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