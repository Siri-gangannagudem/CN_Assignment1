#include <pcap.h>
#include <iostream>
#include <unordered_map>
#include <netinet/ip.h>    
#include <netinet/tcp.h>   
#include <netinet/udp.h>   
#include <arpa/inet.h>     

// Dictionary to store IP flows
std::unordered_map<std::string, int> srcFlows;
std::unordered_map<std::string, int> dstFlows;

// Dictionary to store data transferred per connection
std::unordered_map<std::string, uint64_t> dataTransferred;
std::string maxDataPair;
uint64_t maxDataSize = 0;

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

    // Track flows (count occurrences of each IP as source and destination)
    srcFlows[srcIP]++;
    dstFlows[dstIP]++;

    // Track data transferred per connection
    std::string connectionKey = srcIP + ":" + std::to_string(srcPort) + " -> " + dstIP + ":" + std::to_string(dstPort);
    dataTransferred[connectionKey] += header->len;

    // Check if this is the highest data transfer so far
    if (dataTransferred[connectionKey] > maxDataSize) {
        maxDataSize = dataTransferred[connectionKey];
        maxDataPair = connectionKey;
    }
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

    // Print IP Flow Counts
    std::cout << "Source IP Flows:" << std::endl;
    for (const auto& [ip, count] : srcFlows) {
        std::cout << ip << " -> " << count << " flows" << std::endl;
    }

    std::cout << "\nDestination IP Flows:" << std::endl;
    for (const auto& [ip, count] : dstFlows) {
        std::cout << ip << " -> " << count << " flows" << std::endl;
    }

    // Print highest data transfer connection
    std::cout << "\nConnection with the most data transferred:" << std::endl;
    std::cout << maxDataPair << " -> " << maxDataSize << " bytes" << std::endl;

    return 0;
}
