#include <iostream>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <string.h>

#define HTTP_PORT 80

// Function to check if HTTP request contains login data
bool is_login_attempt(const char* payload) {
    // Simple check for login patterns in HTTP requests (e.g., POST or GET to login endpoint)
    return (strstr(payload, "POST") || strstr(payload, "GET")) && 
           (strstr(payload, "login") || strstr(payload, "Login"));
}

// Packet processing function with the correct callback signature
void process_packet(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ip *ip_header = (struct ip *)(packet + 14);  // IP header is after the Ethernet header
    struct tcphdr *tcp_header = (struct tcphdr *)(packet + 14 + (ip_header->ip_hl << 2));  // TCP header
    
    // Check if the packet is HTTP (port 80)
    if (ntohs(tcp_header->th_dport) == HTTP_PORT || ntohs(tcp_header->th_sport) == HTTP_PORT) {
        // Get payload (after TCP header)
        const char* payload = (char *)(packet + 14 + (ip_header->ip_hl << 2) + (tcp_header->th_off << 2));
        
        // Check for login attempts in the payload
        if (is_login_attempt(payload)) {
            // Calculate content length (you can adjust this depending on your needs)
            size_t content_length = header->len - (14 + (ip_header->ip_hl << 2) + (tcp_header->th_off << 2));
            
            // Accumulate the total length (assuming user is NULL)
            *(size_t*)user += content_length;
        }
    }
}

// Main function to open the pcap file and process packets
int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    size_t total_length = 0;
    
    // Open the pcap file
    handle = pcap_open_offline("captured_traffic.pcap", errbuf);
    if (handle == NULL) {
        std::cerr << "Error opening file: " << errbuf << std::endl;
        return 1;
    }

    // Process packets and accumulate total length
    pcap_loop(handle, 0, process_packet, (u_char*)&total_length);
    
    // Close the pcap file
    pcap_close(handle);
    
    // Output the total length of all login attempt payloads
    std::cout << "Total content length of all login attempts: " << total_length << " bytes" << std::endl;
    
    return 0;
}
