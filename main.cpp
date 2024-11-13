#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <chrono>
#include <cstdlib>
#include <csignal>
#include <atomic>
#include "CaptureManager.hpp"
#include "Analyzers/DHCP/DHCPAnalyzer.hpp"
#include "Analyzers/ARP/ARPAnalyzer.hpp"
#include "Analyzers/STP/STPAnalyzer.hpp"
#include "Hosts/HostManager.hpp"

int main() {
    // Get the network interface from environment variable
    const char* interfaceEnv = "any"; //std::getenv("INTERFACE");
    if (!interfaceEnv) {
        std::cerr << "Error: INTERFACE environment variable is not set." << std::endl;
        return 1;
    }
    std::string interface = interfaceEnv;

    // Get the timeout duration from environment variable
    const char* durationEnv = "-1"; //std::getenv("TIMEOUT");
    if (!durationEnv) {
        std::cerr << "Error: TIMEOUT environment variable is not set." << std::endl;
        return 1;
    }
    std::string durationStr = durationEnv;
    bool isInfinite = (durationStr == "-1");

    // Convert duration to integer if not infinite
    int duration = isInfinite ? 0 : std::stoi(durationStr);

    // Create the host manager
    HostManager hostManager;

    // Create the capture manager
    CaptureManager captureManager(interface);

    // Create analyzers
    DHCPAnalyzer dhcpAnalyzer(hostManager);
    ARPAnalyzer arpAnalyzer(hostManager);
    STPAnalyzer stpAnalyzer(hostManager);

    // Add analyzers to the manager
    captureManager.addAnalyzer(&dhcpAnalyzer);
    captureManager.addAnalyzer(&arpAnalyzer);
    captureManager.addAnalyzer(&stpAnalyzer);

    // Start capturing packets
    std::cout << "Starting packet capture on interface: " << interface << std::endl;

    try {
        captureManager.startCapture();

        if (isInfinite) {
            // Infinite capture loop
            std::cout << "Capturing packets indefinitely. Press Ctrl+C to stop." << std::endl;
            std::this_thread::sleep_for(std::chrono::seconds(1));
        } else {
            // Finite capture
            std::cout << "Capturing packets for " << duration << " seconds" << std::endl;
            for (int i = 0; i < duration; i++) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "Exception occurred during capture: " << e.what() << std::endl;
    }

    // Attempt to stop the capture gracefully
    try {
        std::cout << "Stopping packet capture..." << std::endl;
        captureManager.stopCapture();
        std::cout << "Packet capture stopped." << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Exception occurred while stopping capture: " << e.what() << std::endl;
    }

    // Print the host map
    hostManager.printHostMap();

    std::cout << "Program terminated." << std::endl;
    return 0;
}
