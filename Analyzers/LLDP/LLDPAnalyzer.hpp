#ifndef LLDP_ANALYZER_HPP
#define LLDP_ANALYZER_HPP

#include "../Analyzer.hpp"
#include <string>
#include <map>

// LLDPAnalyzer class (derived from Analyzer)
class LLDPAnalyzer : public Analyzer {
private:
    std::map<std::string, std::map<std::string, std::string>> lldpMap; // Store LLDP details, keyed by MAC address

public:
    // Method to analyze a packet (overrides the virtual method in Analyzer)
    void analyzePacket(pcpp::Packet& parsedPacket) override;

    // Print captured LLDP information
    void printHostMap();
};

#endif // LLDP_ANALYZER_HPP
