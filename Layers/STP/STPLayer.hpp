#ifndef STP_LAYER_HPP
#define STP_LAYER_HPP

#include <cstdint>
#include <cstddef> 
#include <stdexcept>
#include <iostream> 
#include <iomanip>
#include <algorithm>

class STPLayer {
  public: 
    STPLayer(const uint8_t* data, size_t dataLen);
    ~STPLayer();

    struct RootIdentifier {
        uint16_t priority;
        uint8_t systemIDExtension;
        uint64_t systemID;
    } __attribute__((packed));

    struct RootIdentifier getRootIdentifier() const;

    struct BridgeIdentifier {
        uint16_t priority;
        uint8_t systemIDExtension;
        uint64_t systemID;
    } __attribute__((packed));

    struct BridgeIdentifier getBridgeIdentifier() const;

    STPLayer(const STPLayer&) = delete;
    
  private:
    const uint8_t* rawData;
    size_t rawDataLength;

    struct CBDU {
        uint8_t bpduType;
        uint8_t flags;
        uint64_t RootIdentifier;
        uint32_t RootPathCost;
        uint64_t BridgeIdentifier;
        uint16_t PortIdentifier;
        uint16_t MessageAge;
        uint16_t MaxAge;
        uint16_t HelloTime;
        uint16_t ForwardDelay;
    } __attribute__((packed));

    struct CBDU cbdu;

    void parseSTPDU();
    struct CBDU getCBDU() const;

    friend std::ostream& operator<<(std::ostream& os, const STPLayer& layer);
};

#endif // STP_LAYER_HPP
