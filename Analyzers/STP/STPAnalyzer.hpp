#ifndef STP_ANALYZER_HPP
#define STP_ANALYZER_HPP

#include "../Analyzer.hpp"
#include "../../Layers/STP/STPLayer.hpp"

#include <map>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <string>
#include <unordered_map> 

// LLDPAnalyzer class (derived from Analyzer)
class STPAnalyzer : public Analyzer {

public:
    // Method to analyze a packet (overrides the virtual method in Analyzer)
    void analyzePacket(pcpp::Packet& parsedPacket) override;
};

#endif // LLDP_ANALYZER_HPP
