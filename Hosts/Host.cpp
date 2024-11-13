#include "Host.hpp"

void Host::updateProtocolData(ProtocolType protocol, std::unique_ptr<ProtocolData> data) {
    auto& protocolSet = protocols_data[static_cast<size_t>(protocol)];
    auto it = protocolSet.find(data);

    if (it != protocolSet.end()) {
        // Update the timestamp if the entry already exists
        (*it)->timestamp = data->timestamp;
                protocolSet.insert(std::move(data));

    } else {
        // Insert the new entry
        protocolSet.insert(std::move(data));
    }
}