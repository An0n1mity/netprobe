#ifndef DNS_ANALYZER_HPP
#define DNS_ANALYZER_HPP

#include "../Analyzer.hpp"

// DNSAnalyzer (Derived class)
class mDNSAnalyzer : public Analyzer {

private:
    std::map<std::string, std::string> hostnameMap;

public:
    mDNSAnalyzer(HostManager& hostManager) : Analyzer(hostManager) {}
    void analyzePacket(pcpp::Packet& parsedPacket) override;
};

#endif // DNS_ANALYZER_HPP