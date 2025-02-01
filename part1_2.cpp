#include <pcap.h>
#include <iostream>
#include <set>
#include <string>
#include <netinet/ip.h>     // IP header
#include <netinet/tcp.h>    // TCP header
#include <netinet/udp.h>    // UDP header
#include <arpa/inet.h>      // inet_ntoa()
#include <tuple>  // Add this line


// Struct to store unique source-destination pairs
struct Connection {
    std::string srcIP;
    uint16_t srcPort;
    std::string dstIP;
    uint16_t dstPort;
    bool operator<(const Connection &other) const {
        return std::tie(srcIP, srcPort, dstIP, dstPort) < std::tie(other.srcIP, other.srcPort, other.dstIP, other.dstPort);
    }
};

std::set<Connection> uniqueConnections;

// Function to analyze each packet
void analyzePacket(const struct pcap_pkthdr* header, const u_char* packet) {
    struct ip* ipHeader = (struct ip*)(packet + 14); 
    
    if (ipHeader->ip_p != IPPROTO_TCP && ipHeader->ip_p != IPPROTO_UDP) {
        return; 
    }

    std::string srcIP = inet_ntoa(ipHeader->ip_src);
    std::string dstIP = inet_ntoa(ipHeader->ip_dst);
    uint16_t srcPort = 0, dstPort = 0;

    if (ipHeader->ip_p == IPPROTO_TCP) {
        struct tcphdr* tcpHeader = (struct tcphdr*)((u_char*)ipHeader + (ipHeader->ip_hl * 4));
        srcPort = ntohs(tcpHeader->th_sport);
        dstPort = ntohs(tcpHeader->th_dport);
    } else if (ipHeader->ip_p == IPPROTO_UDP) {
        struct udphdr* udpHeader = (struct udphdr*)((u_char*)ipHeader + (ipHeader->ip_hl * 4));
        srcPort = ntohs(udpHeader->uh_sport);
        dstPort = ntohs(udpHeader->uh_dport);
    }

    uniqueConnections.insert({srcIP, srcPort, dstIP, dstPort});
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_offline("3.pcap", errbuf);
    if (handle == nullptr) {
        std::cerr << "Error opening pcap file: " << errbuf << std::endl;
        return 1;
    }

    struct pcap_pkthdr header;  
    const u_char* packet;

    while ((packet = pcap_next(handle, &header)) != nullptr) {
        analyzePacket(&header, packet);
    }

    pcap_close(handle);

    // Print unique source-destination pairs
    std::cout << "Unique Source-Destination Pairs (IP:Port):" << std::endl;
    for (const auto& conn : uniqueConnections) {
        std::cout << conn.srcIP << ":" << conn.srcPort << " -> " << conn.dstIP << ":" << conn.dstPort << std::endl;
    }

    return 0;
}
