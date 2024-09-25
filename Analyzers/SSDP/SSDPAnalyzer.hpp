#ifndef SSDP_ANALYZER_HPP
#define SSDP_ANALYZER_HPP

#include "../Analyzer.hpp"
#include <string>
#include <map>

// SSDPAnalyzer class (derived from Analyzer)
class SSDPAnalyzer : public Analyzer {
private:
    std::map<std::string, std::string> ssdpMap; // Store SSDP details, keyed by USN or Location

public:
    // Method to analyze a packet (overrides the virtual method in Analyzer)
    void analyzePacket(pcpp::Packet& parsedPacket) override;

    // Print captured SSDP information
    void printHostMap();
};

#endif // SSDP_ANALYZER_HPP
