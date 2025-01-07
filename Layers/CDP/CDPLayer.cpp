#include "CDPLayer.hpp"

CDPLayer::CDPLayer(const uint8_t* data, size_t dataLen) : rawData(data), rawDataLength(dataLen) {
    // Check if the data length is valid for CDP
    if (dataLen < 4) {
        throw std::invalid_argument("Invalid CDPDU size");
    }

    // Parse TLVs
    parseTLVs();
}

CDPLayer::~CDPLayer() {
    // Destructor implementation (if needed)
}

void CDPLayer::parseTLVs() {
    size_t offset = 0;

    while (offset < rawDataLength) {
        // Ensure there's at least three bytes remaining for TLV header
        if (rawDataLength - offset < 3) {
            throw std::runtime_error("Incomplete TLV header");
        }

        // Extract TLV type and length (first 2 bytes)
        uint16_t tlvType = (rawData[offset] << 8) | rawData[offset + 1];
        uint16_t tlvLength = (rawData[offset + 2] << 8) | rawData[offset + 3];

        // Ensure there's enough data left for the TLV value
        if (offset + tlvLength > rawDataLength) {
            throw std::runtime_error("TLV length exceeds available data");
        }

        // Extract TLV value
        const uint8_t* tlvValue = rawData + offset;

        // Create a TLV struct and add it to the list
        TLV tlv = {tlvType, tlvLength, tlvValue};
        tlvs.push_back(tlv);

        // Move the offset to the next TLV
        offset += tlvLength;
    }
}

CDPLayer::TLV CDPLayer::getTLV(uint8_t type) const {
    for (const TLV& tlv : tlvs) {
        if (tlv.type == type) {
            return tlv;
        }
    }

    return {0, 0, nullptr};
}

struct CDPLayer::DeviceId CDPLayer::getDeviceId() const {
    TLV tlv = getTLV(CDP_TLV_TYPE_DEVICE_ID);
    DeviceId deviceId;

    // Ensure the TLV has a valid length
    if (tlv.length < 2) {
        return deviceId;
    }

    // Extract the subtype and value
    deviceId.subtype = static_cast<DeviceIdSubtype>(tlv.value[0]);
    deviceId.id = std::string(reinterpret_cast<const char*>(tlv.value + 1), tlv.length - 1);

    return deviceId;
}

// toHexString
std::string toHexString(const uint8_t* data, size_t length) {
    std::ostringstream oss;
    for (size_t i = 0; i < length; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    }
    return oss.str();
}

struct CDPLayer::Addresses CDPLayer::getAddresses() const {
    TLV tlv = getTLV(CDP_TLV_TYPE_ADDRESS);
    Addresses addresses;

    // Ensure the TLV has a valid length
    if (tlv.length < 1) {
        return addresses;
    }

    // Extract the number of addresses offset 4 bytes and convert to integer
    addresses.numberOfAddresses = tlv.value[4] << 24 | tlv.value[5] << 16 | tlv.value[6] << 8 | tlv.value[7];
    // print tlv value
    std::cout << "TLV value: " << toHexString(tlv.value, tlv.length) << std::endl;
    std::cout << "Number of addresses: " << addresses.numberOfAddresses << std::endl;

    // Ensure the TLV has a valid length
    if (tlv.length < 1 + addresses.numberOfAddresses * 5) {
        return addresses;
    }

    // Extract the addresses
    for (size_t i = 0; i < addresses.numberOfAddresses; i++) {
        Address address;
        address.protocolType = tlv.value[8 + i * 5];
        address.protocolLength = tlv.value[9 + i * 5];
        address.protocol = tlv.value[10 + i * 5];
        address.addressLength = tlv.value[11 + i * 5] << 8 | tlv.value[12 + i * 5];
        address.address = tlv.value + 13 + i * 5;
        std::cout << "Protocol type: " << address.protocolType << std::endl;
        std::cout << "Protocol length: " << address.protocolLength << std::endl;
        std::cout << "Protocol: " << address.protocol << std::endl;
        std::cout << "Address length: " << address.addressLength << std::endl;
        std::cout << "Address: " << toHexString(address.address, address.addressLength) << std::endl;
        addresses.addresses.push_back(address);
    }

    return addresses;
}

std::string CDPLayer::getPortId() const {
    TLV tlv = getTLV(CDP_TLV_TYPE_PORT_ID);

    // Ensure the TLV has a valid length
    if (tlv.length < 1) {
        return "";
    }

    return std::string(reinterpret_cast<const char*>(tlv.value), tlv.length);
}

std::vector<struct CDPLayer::SystemCapability> CDPLayer::getCapabilities() const {
    TLV tlv = getTLV(CDP_TLV_TYPE_CAPABILITIES);
    std::vector<struct SystemCapability> capabilities;

    // Ensure the TLV has the expected length (4 bytes: 2 for supported, 2 for enabled)
    if (tlv.length < 4) {
        return capabilities;  // Return an empty vector if the TLV is invalid
    }

    // Extract the system capabilities and enabled capabilities (each 2 bytes)
    uint16_t supportedCapabilities = ntohs(*reinterpret_cast<const uint16_t*>(tlv.value));
    uint16_t enabledCapabilities = ntohs(*reinterpret_cast<const uint16_t*>(tlv.value + 2));

    // Add each capability to the vector based on the bitmask
    if (supportedCapabilities & CAPABILITY_ROUTER) {
        capabilities.push_back({CAPABILITY_ROUTER, static_cast<bool>(enabledCapabilities & CAPABILITY_ROUTER)});
    }
    if (supportedCapabilities & CAPABILITY_TRANSPARENT_BRIDGE) {
        capabilities.push_back({CAPABILITY_TRANSPARENT_BRIDGE, static_cast<bool>(enabledCapabilities & CAPABILITY_TRANSPARENT_BRIDGE)});
    }
    if (supportedCapabilities & CAPABILITY_SOURCE_ROUTE_BRIDGE) {
        capabilities.push_back({CAPABILITY_SOURCE_ROUTE_BRIDGE, static_cast<bool>(enabledCapabilities & CAPABILITY_SOURCE_ROUTE_BRIDGE)});
    }
    if (supportedCapabilities & CAPABILITY_SWITCH) {
        capabilities.push_back({CAPABILITY_SWITCH, static_cast<bool>(enabledCapabilities & CAPABILITY_SWITCH)});
    }
    if (supportedCapabilities & CAPABILITY_HOST) {
        capabilities.push_back({CAPABILITY_HOST, static_cast<bool>(enabledCapabilities & CAPABILITY_HOST)});
    }
    if (supportedCapabilities & CAPABILITY_IGMP) {
        capabilities.push_back({CAPABILITY_IGMP, static_cast<bool>(enabledCapabilities & CAPABILITY_IGMP)});
    }
    if (supportedCapabilities & CAPABILITY_REPEATER) {
        capabilities.push_back({CAPABILITY_REPEATER, static_cast<bool>(enabledCapabilities & CAPABILITY_REPEATER)});
    }
    if (supportedCapabilities & CAPABILITY_VOIP_PHONE) {
        capabilities.push_back({CAPABILITY_VOIP_PHONE, static_cast<bool>(enabledCapabilities & CAPABILITY_VOIP_PHONE)});
    }
    if (supportedCapabilities & CAPABILITY_REMOTELY_MANAGED) {
        capabilities.push_back({CAPABILITY_REMOTELY_MANAGED, static_cast<bool>(enabledCapabilities & CAPABILITY_REMOTELY_MANAGED)});
    }
    if (supportedCapabilities & CAPABILITY_CVTA) {
        capabilities.push_back({CAPABILITY_CVTA, static_cast<bool>(enabledCapabilities & CAPABILITY_CVTA)});
    }
    if (supportedCapabilities & CAPABILITY_TWO_PORT_MAC_RELAY) {
        capabilities.push_back({CAPABILITY_TWO_PORT_MAC_RELAY, static_cast<bool>(enabledCapabilities & CAPABILITY_TWO_PORT_MAC_RELAY)});
    }

    return capabilities;
}
