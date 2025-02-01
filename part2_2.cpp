#include <pcap.h>
#include <iostream>
#include <string>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#define TARGET_IP "192.168.10.50"
#define SUCCESS_PASSWORD "securepassword"

void processPacket(u_char *userData, const struct pcap_pkthdr* header, const u_char* data) {
    struct ip* ipHeader = (struct ip*)(data + 14); // Skip Ethernet header
    struct tcphdr* tcpHeader = (struct tcphdr*)(data + 14 + (ipHeader->ip_hl << 2)); // Skip IP header
    
    if (ipHeader->ip_p == IPPROTO_TCP) {
        std::string srcIP = std::string(inet_ntoa(ipHeader->ip_src));
        
        // Filter for packets from IP 192.168.10.50
        if (srcIP == TARGET_IP) {
            const char* payload = (char*)(data + 14 + (ipHeader->ip_hl << 2) + (tcpHeader->th_off << 2));
            int payloadLength = header->len - (14 + (ipHeader->ip_hl << 2) + (tcpHeader->th_off << 2));

            std::string packetData(payload, payloadLength);

            if (packetData.find("POST") != std::string::npos) {
                
                // Check if the packet contains the successful password
                size_t passwordPos = packetData.find(SUCCESS_PASSWORD);
                if (passwordPos != std::string::npos) {
                    std::cout << "Found successful login attempt!" << std::endl;
                    
                    // Extract the credentials 
                    size_t userPos = packetData.find("username=");
                    size_t passPos = packetData.find("password=");
                    if (userPos != std::string::npos && passPos != std::string::npos) {
                        std::string username = packetData.substr(userPos + 9, passPos - userPos - 10); // 9 is length of "username="
                        std::string password = packetData.substr(passPos + 9, packetData.find('&', passPos) - passPos - 9); // 9 is length of "password="

                        // Output the credentials for the successful login attempt
                        std::cout << "Q2. Successful login credentials:" << std::endl;
                        std::cout << "Username: " << username << std::endl;
                        std::cout << "Password: " << password << std::endl;
                    }

                    // Extract the client's source port (TCP source port)
                    uint16_t sourcePort = ntohs(tcpHeader->th_sport);
                    std::cout << "Q3. Client's source port: " << sourcePort << std::endl;

                    return;
                }
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

    pcap_loop(handle, 0, processPacket, nullptr);
    
    pcap_close(handle);
    return 0;
}
