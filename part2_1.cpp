#include <pcap.h>
#include <iostream>
#include <string>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#define TARGET_IP "192.168.10.50"

void processPacket(u_char *userData, const struct pcap_pkthdr* header, const u_char* data) {
    struct ip* ipHeader = (struct ip*)(data + 14); 
    struct tcphdr* tcpHeader = (struct tcphdr*)(data + 14 + (ipHeader->ip_hl << 2)); 
    
    // Ensure it's a TCP packet
    if (ipHeader->ip_p == IPPROTO_TCP) {
        std::string srcIP = std::string(inet_ntoa(ipHeader->ip_src));
        
        // Filter for packets from IP 192.168.10.50
        if (srcIP == TARGET_IP) {
            const char* payload = (char*)(data + 14 + (ipHeader->ip_hl << 2) + (tcpHeader->th_off << 2));
            int payloadLength = header->len - (14 + (ipHeader->ip_hl << 2) + (tcpHeader->th_off << 2));

            std::string packetData(payload, payloadLength);

            // Check if it contains HTTP POST (to count login attempts)
            if (packetData.find("POST") != std::string::npos) {
                static int loginAttempts = 0;
                loginAttempts++;

                // Store the login attempt count in the userData for later use
                *(int*)userData = loginAttempts;
            }
        }
    }
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_offline("captured_traffic.pcap", errbuf);
    
    if (handle == nullptr) {
        std::cerr << "Error opening pcap file: " << errbuf << std::endl;
        return 1;
    }

    int loginAttempts = 0; 
    pcap_loop(handle, 0, processPacket, (u_char*)&loginAttempts);
    
    std::cout << "Number of login attempts: " << loginAttempts << std::endl;
    
    pcap_close(handle);
    return 0;
}
