#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <chrono>
#include <cstdlib>
#include <boost/asio.hpp>
#include <boost/asio/signal_set.hpp>
#include <atomic>
#include "CaptureManager.hpp"
#include "Analyzers/DHCP/DHCPAnalyzer.hpp"
#include "Analyzers/mDNS/mDNSAnalyzer.hpp"
#include "Analyzers/ARP/ARPAnalyzer.hpp"
#include "Analyzers/STP/STPAnalyzer.hpp"
#include "Hosts/HostManager.hpp"
#include <atomic> // For atomic flag

int main() {
    loadVendorDatabase("./build/manuf", vendorDatabase);

    // Get the network interface from environment variable
    const char* interfaceEnv = "eth0";
    if (!interfaceEnv) {
        std::cerr << "Error: INTERFACE environment variable is not set." << std::endl;
        return 1;
    }
    std::string interface = interfaceEnv;

    // Get the timeout duration from environment variable
    const char* durationEnv = "-1";
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

    boost::asio::io_context io_context;
    boost::asio::signal_set signals(io_context, SIGUSR1);
    signals.async_wait([&hostManager](const boost::system::error_code& error, int signum) {
        if (!error) {
            std::cout << "Signal (" << signum << ") received, dumping hosts file..." << std::endl;
            hostManager.dumpHostsToFile("hosts.json");
        }
    });

    // Start the IO context in a separate thread
    std::thread io_thread([&io_context]() { io_context.run(); });

    // Create the capture manager
    CaptureManager captureManager(interface);

    // Create analyzers
    DHCPAnalyzer dhcpAnalyzer(hostManager);
    mDNSAnalyzer mdnsAnalyzer(hostManager);
    ARPAnalyzer arpAnalyzer(hostManager);
    STPAnalyzer stpAnalyzer(hostManager);

    // Add analyzers to the manager
    captureManager.addAnalyzer(&dhcpAnalyzer);
    captureManager.addAnalyzer(&arpAnalyzer);
    captureManager.addAnalyzer(&stpAnalyzer);

    // Start capturing packets
    std::cout << "Starting packet capture on interface: " << interface << std::endl;

    std::atomic<bool> running(true); // Atomic flag for the infinite loop
    try {
        captureManager.startCapture();

        if (isInfinite) {
            std::cout << "Capturing packets indefinitely. Press Ctrl+C to stop." << std::endl;

            // Infinite loop controlled by the atomic flag
            while (running) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
        } else {
            std::cout << "Capturing packets for " << duration << " seconds" << std::endl;

            // Finite loop for the given duration
            for (int i = 0; i < duration; i++) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "Exception occurred during capture: " << e.what() << std::endl;
    }

    // Stop the infinite loop when a signal (e.g., SIGINT) is received
    signals.async_wait([&running](const boost::system::error_code& error, int) {
        if (!error) {
            running = false; // Break the loop
        }
    });

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
    hostManager.dumpHostsToFile("hosts.json");

    std::cout << "Program terminated." << std::endl;

    io_thread.join();
    return 0;
}

