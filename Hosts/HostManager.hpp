#ifndef HOST_MANAGER_HPP
#define HOST_MANAGER_HPP

#include "Host.hpp"

/**
 * @class MacAddressHash
 * 
 * @brief Custom hash function for pcpp::MacAddress.
 */
struct MacAddressHash {
    std::size_t operator()(const pcpp::MacAddress& mac) const {
        // Example hash implementation based on the byte array representation of the MAC address
        return std::hash<std::string>()(mac.toString());
    }
};

/**
 * @class MacAddressEqual
 * 
 * @brief Custom equality function for pcpp::MacAddress.
 */
struct MacAddressEqual {
    bool operator()(const pcpp::MacAddress& lhs, const pcpp::MacAddress& rhs) const {
        return lhs == rhs; // Assuming operator== is defined for pcpp::MacAddress
    }
};

/**
 * @class IPAddressHash
 * 
 * @brief Custom hash function for pcpp::IPAddress.
 */
struct IPAddressHash {
    std::size_t operator()(const pcpp::IPAddress& ip) const {
        // Example hash implementation based on the byte array representation of the IP address
        return std::hash<std::string>()(ip.toString());
    }
};

/**
 * @class IPAddressEqual
 * 
 * @brief Custom equality function for pcpp::IPAddress.
 */
struct IPAddressEqual {
    bool operator()(const pcpp::IPAddress& lhs, const pcpp::IPAddress& rhs) const {
        return lhs == rhs; // Assuming operator== is defined for pcpp::IPAddress
    }
};


/**
 * @class HostManager
 * @brief Manages hosts and their information.
 * 
 * The HostManager class is responsible for managing hosts, updating their information,
 * and maintaining a JSON representation of the hosts. It provides methods to update
 * hosts with protocol-specific data, update the JSON representation, dump host information
 * to a file, print the host map, and retrieve the host map.
 */
class HostManager {
public:
    // Add or update a host with information from a specific protocol
    void updateHost(ProtocolType protocol, std::unique_ptr<ProtocolData> data);
    // Update a host in the hostsJson array
    void updateHostJson(const Host& host);
    // Update report file with hosts information
    void dumpHostsToFile(const std::string& filename);
    // Print the host map	
    void printHostMap();
    // Get the host map
    const std::unordered_map<pcpp::MacAddress, Host, MacAddressHash, MacAddressEqual>& getHostMap() const;
private:
    std::unordered_map<pcpp::MacAddress, Host, MacAddressHash, MacAddressEqual> hostMap;
    Json::Value hostsJson;
    // Unknown mac address counter
    int unknownMacCounter = 0;
};

#endif // HOST_MANAGER_HPP