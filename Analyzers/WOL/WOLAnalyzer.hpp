#ifndef WOL_ANALYZER_HPP
#define WOL_ANALYZER_HPP

#include "../Analyzer.hpp"

class WOLAnalyzer : public Analyzer {
  private:
    std::unordered_set<pcpp::MacAddress, MacAddressHash, MacAddressEqual> wolSourceMacs;
    std::unordered_set<pcpp::MacAddress, MacAddressHash, MacAddressEqual> wolTargetMacs;
  public:
    WOLAnalyzer(HostManager& hostManager) : Analyzer(hostManager) {}
    void analyzePacket(pcpp::Packet& parsedPacket) override;
    std::unordered_set<pcpp::MacAddress, MacAddressHash, MacAddressEqual> getSourceMacs() const { return wolSourceMacs; }
    std::unordered_set<pcpp::MacAddress, MacAddressHash, MacAddressEqual> getTargetMacs() const { return wolTargetMacs; }
};

#endif // WOL_ANALYZER_HPP