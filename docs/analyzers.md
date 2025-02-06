# Adding a New Analyzer

To add a new analyzer to the NetProbe application, follow these steps:

## 1. Create the Analyzer Class

1.1. Create a new header file for your analyzer in the `Analyzers` directory, e.g., `NewAnalyzer.hpp`:

```cpp
#ifndef NEW_ANALYZER_HPP
#define NEW_ANALYZER_HPP

#include "../Analyzer.hpp"

// NewAnalyzer class (derived from Analyzer)
/**
 * @class NewAnalyzer
 * @brief Analyzes NewProtocol packets and updates the host manager.
 */
class NewAnalyzer : public Analyzer {
public:
  NewAnalyzer(HostManager& hostManager) : Analyzer(hostManager) {}
  void analyzePacket(pcpp::Packet& parsedPacket) override;
};

#endif // NEW_ANALYZER_HPP
```

1.2. Create a new source file for your analyzer in the `Analyzers` directory, e.g., `NewAnalyzer.cpp`:

```cpp
#include "NewAnalyzer.hpp"

void NewAnalyzer::analyzePacket(pcpp::Packet& parsedPacket) {
  // Implement the packet analysis logic here
}
```

## 2. Update the CaptureManager

2.1. Include your new analyzer in the `main.cpp` file:

```cpp
#include "Analyzers/NewAnalyzer.hpp"
```

2.2. Instantiate and add your new analyzer to the `CaptureManager` in the `main` function:

```cpp
int main() {
  // ...
  NewAnalyzer newAnalyzer(hostManager);
  captureManager.addAnalyzer(&newAnalyzer);
  // ...
}
```

## 3. Update ProtocolData and HostManager

3.1. Edit `ProtocolData.hpp` to add a new struct for your protocol data:

```cpp
struct NewProtocolData : public ProtocolData {
  // Add fields specific to NewProtocol
  std::string exampleField;

  NewProtocolData() : ProtocolData(ProtocolType::NewProtocol) {}
};
```

3.2. Update `HostManager` to handle the new protocol:

```cpp
void HostManager::updateHost(ProtocolType protocol, std::unique_ptr<ProtocolData> data) {
  // Add a case for the new protocol
  switch (protocol) {
    case ProtocolType::NewProtocol: {
      NewProtocolData* newProtocolData = dynamic_cast<NewProtocolData*>(data.get());
      if (newProtocolData) {
        processHost(newProtocolData->exampleField, ProtocolType::NewProtocol);
      }
      break;
    }
    // Existing cases...
  }
}
```

3.3. Update `Host` to store and retrieve the new protocol data:

```cpp
void Host::updateProtocolData(ProtocolType protocol, std::unique_ptr<ProtocolData> data) {
  // Add logic to handle NewProtocolData
  if (protocol == ProtocolType::NewProtocol) {
    auto newProtocolData = dynamic_cast<NewProtocolData*>(data.get());
    if (newProtocolData) {
      // Store newProtocolData
    }
  }
  // Existing logic...
}
```

## 4. Build and Test

4.1. Ensure your project builds successfully:

```sh
mkdir build
cd build
cmake ..
make
```

4.2. Run the application and verify that your new analyzer processes packets as expected.

By following these steps, you can add a new analyzer to the NetProbe application to handle specific protocol packets and update the host manager accordingly.

## 5. Create a Custom Layer (if needed)

If the protocol you want to analyze is not supported by PcapPlusPlus, you will need to create a custom Layer class before implementing your analyzer.

5.1. Create a new header file for your custom layer in the `Layers` directory, e.g., `NewProtocolLayer.hpp`:

```cpp
#ifndef NEW_PROTOCOL_LAYER_HPP
#define NEW_PROTOCOL_LAYER_HPP

#include "Layer.h"

/**
 * @class NewProtocolLayer
 * @brief Represents the NewProtocol layer.
 */
class NewProtocolLayer : public pcpp::Layer {
public:
  NewProtocolLayer(uint8_t* data, size_t dataLen, pcpp::Layer* prevLayer, pcpp::Packet* packet)
    : pcpp::Layer(data, dataLen, prevLayer, packet) {
    m_Protocol = pcpp::ProtocolType::NewProtocol;
  }

  void parseNextLayer() override;
  size_t getHeaderLen() const override;
  void computeCalculateFields() override;
  std::string toString() const override;
};

#endif // NEW_PROTOCOL_LAYER_HPP
```

5.2. Create a new source file for your custom layer in the `Layers` directory, e.g., `NewProtocolLayer.cpp`:

```cpp
#include "NewProtocolLayer.hpp"

void NewProtocolLayer::parseNextLayer() {
  // Implement the logic to parse the next layer
}

size_t NewProtocolLayer::getHeaderLen() const {
  // Return the header length of the NewProtocol layer
}

void NewProtocolLayer::computeCalculateFields() {
  // Implement the logic to compute fields
}

std::string NewProtocolLayer::toString() const {
  // Return a string representation of the NewProtocol layer
}
```

5.3. Register your custom layer in the `main.cpp` file:

```cpp
pcpp::ProtocolType::NewProtocol = pcpp::registerProtocol("NewProtocol", "New Protocol", 12345);
pcpp::Layer::registerProtocol(pcpp::ProtocolType::NewProtocol, pcpp::Layer::createLayer<NewProtocolLayer>);
```

After creating the custom layer, you can proceed with the steps to add a new analyzer as described above.