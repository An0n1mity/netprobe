cmake_minimum_required(VERSION 3.5.0)
project(cartographie-passive VERSION 0.1.0 LANGUAGES C CXX)

#FILE(GLOB sources capture/src/*.cpp 
#  capture/src/application/*.cpp
#  capture/src/data-link/*.cpp
#  capture/src/network/*.cpp
#  capture/src/presentation/*.cpp
#  capture/src/session/*.cpp
#  capture/src/transport/*.cpp
#)

include(FindPCAP.cmake)
find_package(PkgConfig REQUIRED)
find_package(PcapPlusPlus REQUIRED)
pkg_check_modules(JSONCPP jsoncpp)
link_libraries(${JSONCPP_LIBRARIES})

include_directories("/usr/local/include/pcapplusplus")
include_directories(${PCAP_INCLUDE_DIR} ${JSONCPP_INCLUDE_DIRS} ${PcapPlusPlus_INCLUDE_DIRS})

#add_executable(cartographie-passive ${sources})
add_executable(cartographie-passive main.cpp "Analyzers/DHCP/DHCPAnalyzer.cpp" "Analyzers/mDNS/mDNSAnalyzer.cpp" "Analyzers/ARP/ARPAnalyzer.cpp")

target_link_libraries(cartographie-passive ${PCAP_LIBRARY} ${JSONCPP_LIBRARIES} Pcap++ Packet++ Common++ pcap pthread)

