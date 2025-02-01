

#include <pcap.h>
#include <iostream>
#include <vector>
#include <algorithm>
#include <map>  
#include <fstream>
#include <cstdlib>

struct PacketStats {
    uint64_t totalBytes = 0;
    uint64_t totalPackets = 0;
    uint64_t minPacketSize = UINT64_MAX;
    uint64_t maxPacketSize = 0;
    double averagePacketSize = 0.0;
    std::vector<uint64_t> packetSizes;
    std::map<uint64_t, uint64_t> sizeDistribution; 
};

void analyzePacket(const struct pcap_pkthdr* header, const u_char* data, PacketStats& stats) {
    uint64_t packetSize = header->len;
    stats.totalBytes += packetSize;
    stats.totalPackets++;
    stats.minPacketSize = std::min(stats.minPacketSize, packetSize);
    stats.maxPacketSize = std::max(stats.maxPacketSize, packetSize);
    stats.packetSizes.push_back(packetSize);
    
    stats.sizeDistribution[packetSize]++;
}

void computeMetrics(PacketStats& stats) {
    if (stats.totalPackets > 0) {
        stats.averagePacketSize = static_cast<double>(stats.totalBytes) / stats.totalPackets;
    }
}

void printMetrics(const PacketStats& stats) {
    std::cout << "Total Bytes: " << stats.totalBytes << std::endl;
    std::cout << "Total Packets: " << stats.totalPackets << std::endl;
    std::cout << "Min Packet Size: " << stats.minPacketSize << std::endl;
    std::cout << "Max Packet Size: " << stats.maxPacketSize << std::endl;
    std::cout << "Average Packet Size: " << stats.averagePacketSize << std::endl;
}

void plotHistogram(const PacketStats& stats) {
    std::ofstream dataFile("data.dat");

    for (const auto& entry : stats.sizeDistribution) {
        dataFile << entry.first << " " << entry.second << std::endl;
    }

    dataFile.close();

    std::system("gnuplot -e \"set terminal png size 800,600; set output 'histogram.png'; "
                "set boxwidth 0.9 relative; set style fill solid; "
                "set xlabel 'Packet Size (bytes)'; set ylabel 'Frequency'; "
                "set title 'Packet Size Distribution'; "
                "plot 'data.dat' using 1:2 with boxes lc rgb 'blue'\"");
}


int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_offline("3.pcap", errbuf);
    if (handle == nullptr) {
        std::cerr << "Error opening pcap file: " << errbuf << std::endl;
        return 1;
    }

    PacketStats stats;
    const u_char* packet;
    struct pcap_pkthdr header;

    while ((packet = pcap_next(handle, &header)) != nullptr) {
        analyzePacket(&header, packet, stats);
    }

    computeMetrics(stats);
    printMetrics(stats);

    pcap_close(handle);

    plotHistogram(stats);  

    std::cout << "Histogram saved as 'histogram.png'." << std::endl;

    return 0;
}

