#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "plus.h"


void usage() {
	printf("syntax: send-arp-test <interface>\n");
	printf("sample: send-arp-test wlan0\n");
}

Ip getIPAddress (char* dev){
    int sock;
    struct ifreq ifr;
    uint32_t myip;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy((char*)ifr.ifr_name, dev, IFNAMSIZ -1);
    ioctl(sock, SIOCGIFADDR, &ifr);
    close(sock);
    myip = ntohl(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr.s_addr);

    return myip;
}

Mac getMacAddress (char* dev){
    int sock;
    struct ifreq ifr;
    Mac mymac;

    sock = socket(AF_INET,SOCK_DGRAM,0);
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy((char*)ifr.ifr_name, (const char*)dev, IFNAMSIZ-2);
    ioctl(sock,SIOCGIFHWADDR,&ifr);
    close(sock);
    mymac = (uint8_t*)ifr.ifr_hwaddr.sa_data;
    return mymac;
}

void send_packet(pcap_t* handle, Mac eth_dmac, Mac eth_smac, uint16_t op, Mac arp_smac, Ip arp_sip, Mac arp_tmac, Ip arp_tip ){
    EthArpPacket packet;
    packet.eth_.dmac_ = eth_dmac;
    packet.eth_.smac_ = eth_smac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = op;
    packet.arp_.smac_ = arp_smac;
    packet.arp_.sip_ = arp_sip;
    packet.arp_.tmac_ = arp_tmac;
    packet.arp_.tip_ = arp_tip;

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

}

void receive_packet(pcap_t* handle, Mac& smac, Ip sip){
    while (true) {
            struct pcap_pkthdr* header;
            const u_char* packet;
            int res = pcap_next_ex(handle, &header, &packet);
            if (res == 0) continue;
            if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
                printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
                break;
            }

            struct EthArpPacket* etharp = (EthArpPacket*) packet;

            if (ntohs(etharp->eth_.type_) == EthHdr::Arp && ntohs(etharp -> arp_.op_) == ArpHdr::Reply && etharp->arp_.sip() == sip){ 
                smac = etharp->arp_.smac();
                printf("smac: %s\n",std::string(smac).c_str());
                break;
            }else{
                printf("wrong packet\n");
                printf("smac: %s\n",std::string(smac).c_str());
                printf("%d\n",ntohs(etharp->eth_.type_));
                printf("%d\n",ntohs(etharp->arp_.op_));
                printf("Ip(myip) : %s\n\n",std::string(etharp->arp_.sip()).c_str());
            }
    }
}

int main(int argc, char* argv[]) {
    if (argc < 4) {
        usage();
        return -1;
    }

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

    Ip myip = getIPAddress(dev);
    Mac mymac = getMacAddress(dev);

    int cnt = argc-2;
    for(int i =2;cnt>0;i=i+2,cnt=cnt-2){

        Ip sip = Ip(argv[i]); //sender
        Ip tip = Ip(argv[i+1]); //gateway
        Mac smac;

        send_packet(handle, Mac::broadcastMac(), mymac, htons(ArpHdr::Request),mymac, htonl(myip), Mac::nullMac(), htonl(sip));
        receive_packet(handle,smac,sip);
        printf("smac: %s\n",std::string(smac).c_str());
        send_packet(handle, smac, mymac, htons(ArpHdr::Reply),mymac, htonl(tip), smac, htonl(sip));
        printf("finished\n\n");

    }

    pcap_close(handle);
}
