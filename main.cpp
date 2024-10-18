#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <chrono>
#include "CaptureManager.hpp"
#include "Analyzers/DHCP/DHCPAnalyzer.hpp"
#include "Analyzers/mDNS/mDNSAnalyzer.hpp"
#include "Analyzers/ARP/ARPAnalyzer.hpp"
#include "Analyzers/SSDP/SSDPAnalyzer.hpp"
#include "Analyzers/LLDP/LLDPAnalyzer.hpp"
#include "Analyzers/CDP/CDPAnalyzer.hpp"

int main() {
    // Replace with the actual IP address of the interface you want to capture on
    std::string interface = "eth0";

    // Create the capture manager
    CaptureManager captureManager(interface);

    // Create analyzers
    DHCPAnalyzer dhcpAnalyzer;
    mDNSAnalyzer dnsAnalyzer;
    ARPAnalyzer arpAnalyzer;
    SSDPAnalyzer ssdpAnalyzer;
    LLDPAnalyzer lldpAnalyzer;
    CDPAnalyzer cdpAnalyzer;

    // Add analyzers to the manager
    //captureManager.addAnalyzer(&dhcpAnalyzer);
    //captureManager.addAnalyzer(&dnsAnalyzer);
    //captureManager.addAnalyzer(&arpAnalyzer);
    captureManager.addAnalyzer(&ssdpAnalyzer);
    captureManager.addAnalyzer(&lldpAnalyzer);
    captureManager.addAnalyzer(&cdpAnalyzer);

    // Start capturing packets
    captureManager.startCapture();

    // Capture for a certain duration
    std::cout << "Capturing packets for 5 seconds..." << std::endl;
    std::this_thread::sleep_for(std::chrono::seconds(5));

    // Stop capturing
    captureManager.stopCapture();

    // Print results from Analyzers
    //dhcpAnalyzer.printHostMap();
    //arpAnalyzer.printHostMap();
    //ssdpAnalyzer.printHostMap();
    //lldpAnalyzer.printHostMap();
    cdpAnalyzer.printHostMap();

    return 0;
}