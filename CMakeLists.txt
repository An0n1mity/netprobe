cmake_minimum_required(VERSION 3.5.0)
project(cartographie-passive VERSION 0.1.0 LANGUAGES C CXX)

include(FindPCAP.cmake)
find_package(PkgConfig REQUIRED)
find_package(PcapPlusPlus REQUIRED)
pkg_check_modules(JSONCPP jsoncpp)
link_libraries(${JSONCPP_LIBRARIES})

include_directories("/usr/local/include/pcapplusplus")
include_directories(${PCAP_INCLUDE_DIR} ${JSONCPP_INCLUDE_DIRS} ${PcapPlusPlus_INCLUDE_DIRS})

# Collect source files
file(GLOB_RECURSE sources
    "main.cpp"
    "Analyzers/DHCP/*.cpp"
    "Analyzers/mDNS/*.cpp"
    "Analyzers/ARP/*.cpp"
    "Analyzers/SSDP/*.cpp"
    "Analyzers/LLDP/*.cpp"
    "Analyzers/STP/*.cpp"
    "Analyzers/CDP/*.cpp"
    "Analyzers/WOL/*.cpp"
    "Layers/LLDP/*.cpp"
    "Layers/STP/*.cpp"
    "Hosts/*.cpp"
)

add_executable(cartographie-passive ${sources})

target_link_libraries(cartographie-passive ${PCAP_LIBRARY} ${JSONCPP_LIBRARIES} Pcap++ Packet++ Common++ pcap pthread)
