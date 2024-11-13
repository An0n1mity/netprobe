#include "HostManager.hpp"

Json::Value HostManager::protocolDataToJson(const ProtocolData& data) {
    Json::Value json;
    switch (data.getProtocolType()) {
        case ProtocolType::ARP: {
            const ARPData& arpData = dynamic_cast<const ARPData&>(data);
            json["senderMac"] = arpData.senderMac.toString();
            json["senderIp"] = arpData.senderIp.toString();
            json["targetIp"] = arpData.targetIp.toString();
            break;
        }
        case ProtocolType::DHCP: {
            const DHCPData& dhcpData = dynamic_cast<const DHCPData&>(data);
            json["clientMac"] = dhcpData.clientMac.toString();
            json["ipAddress"] = dhcpData.ipAddress.toString();
            json["hostname"] = dhcpData.hostname;
            json["dhcpServerIp"] = dhcpData.dhcpServerIp.toString();
            json["gatewayIp"] = dhcpData.gatewayIp.toString();
            json["dnsServerIp"] = dhcpData.dnsServerIp.toString();
            break;
        }
        case ProtocolType::STP: {
            const STPData& stpData = dynamic_cast<const STPData&>(data);
            json["rootIdentifier"]["priority"] = stpData.rootIdentifier.priority;
            json["rootIdentifier"]["systemIDExtension"] = stpData.rootIdentifier.systemIDExtension;
            json["rootIdentifier"]["systemID"] = stpData.rootIdentifier.systemID;
            json["bridgeIdentifier"]["priority"] = stpData.bridgeIdentifier.priority;
            json["bridgeIdentifier"]["systemIDExtension"] = stpData.bridgeIdentifier.systemIDExtension;
            json["bridgeIdentifier"]["systemID"] = stpData.bridgeIdentifier.systemID;
            break;
        }
    }
    return json;
}

void HostManager::updateHost(ProtocolType protocol, std::unique_ptr<ProtocolData> data) {
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
                if(!senderIp.isZero())
                    host.setIPAddress(senderIp);
                host.updateProtocolData(ProtocolType::ARP, std::move(data));
            } else {
                Host host(senderIp, senderMac);
                host.updateProtocolData(ProtocolType::ARP, std::move(data));
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
            pcpp::IPAddress dhcpServerIp = dhcpData->dhcpServerIp;
            pcpp::IPAddress gatewayIp = dhcpData->gatewayIp;
            pcpp::IPAddress dnsServerIp = dhcpData->dnsServerIp;

            // Check if the host already exists
            if (hostMap.find(clientMac) != hostMap.end()) {
                Host& host = hostMap[clientMac];
                if(!ipAddress.isZero())
                    host.setIPAddress(ipAddress);
                host.setHostName(hostname);
                host.updateProtocolData(ProtocolType::DHCP, std::move(data));
            } else {
                Host host(ipAddress, clientMac, hostname);
                host.updateProtocolData(ProtocolType::DHCP, std::move(data));
                hostMap[clientMac] = std::move(host);
            }
            break;
        }
        case ProtocolType::STP: {
            STPData* stpData = dynamic_cast<STPData*>(data.get());
            if (stpData == nullptr) {
                return;
            }
            STPLayer::RootIdentifier rootIdentifier = stpData->rootIdentifier;
            STPLayer::BridgeIdentifier bridgeIdentifier = stpData->bridgeIdentifier;

            // Check if the host already exists
            if (hostMap.find(pcpp::MacAddress::Zero) != hostMap.end()) {
                Host& host = hostMap[pcpp::MacAddress::Zero];
                host.updateProtocolData(ProtocolType::STP, std::move(data));
            } else {
                Host host;
                host.updateProtocolData(ProtocolType::STP, std::move(data));
                hostMap[pcpp::MacAddress::Zero] = std::move(host);
            }
            break;
        }
    }
}

void HostManager::printHostMap() {
    for (const auto& host : hostMap) {
        std::cout << host.second << std::endl;
    }
}