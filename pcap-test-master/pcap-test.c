#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <./libnet/include/libnet.h>
//#include <libnet.h>


void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param  = {
	.dev_ = NULL
};

void packet_parsing(const u_char* packet, uint psize){

    //u_int16_t type;
    u_int8_t* des_mac;
    u_int8_t* src_mac;

    u_int32_t  des_ip;
    u_int32_t  src_ip;

    u_int32_t des_ip_pack[4];
    u_int32_t src_ip_pack[4];

    const u_char* payload;

    struct libnet_ethernet_hdr* eth = (struct libnet_ethernet_hdr*) packet;
    packet += 14;

    struct libnet_ipv4_hdr* ip = (struct libnet_ipv4_hdr*) packet;
    packet += 20;

    struct libnet_tcp_hdr* tcp = (struct libnet_tcp_hdr*) packet;
    payload = packet + 20;



    if (ntohs(eth->ether_type) == ETHERTYPE_IP && ip->ip_p == IPPROTO_TCP) {
        des_mac = eth->ether_dhost;
        src_mac = eth->ether_shost;

        des_ip = ntohl(ip->ip_dst.s_addr);
        src_ip = ntohl(ip->ip_src.s_addr);

        src_ip_pack[0] = (src_ip & 0xFF000000)>>24;
        src_ip_pack[1] = (src_ip & 0x00FF0000)>>16;
        src_ip_pack[2] = (src_ip & 0x0000FF00)>>8;
        src_ip_pack[3] = (src_ip & 0x000000FF);

        des_ip_pack[0] = (des_ip & 0xFF000000)>>24;
        des_ip_pack[1] = (des_ip & 0x00FF0000)>>16;
        des_ip_pack[2] = (des_ip & 0x0000FF00)>>8;
        des_ip_pack[3] = (des_ip & 0x000000FF);


        printf("source mac : %0x:%0x:%0x:%0x:%0x:%0x \n",src_mac[0],src_mac[1],src_mac[2],src_mac[3],src_mac[4],src_mac[5]);
        printf("destination mac : %0x:%0x:%0x:%0x:%0x:%0x \n\n",des_mac[0],des_mac[1],des_mac[2],des_mac[3],des_mac[4],des_mac[5]);

        printf("source ip : %d.%d.%d.%d\n",src_ip_pack[0],src_ip_pack[1],src_ip_pack[2],src_ip_pack[3]);
        printf("destination ip : %d.%d.%d.%d\n\n",des_ip_pack[0],des_ip_pack[1],des_ip_pack[2],des_ip_pack[3]);

        printf("source port: %d\n",ntohs(tcp->th_sport));
        printf("destination port: %d\n\n",ntohs(tcp->th_dport));

        printf("payload: ");

        if (psize >54){
            for (int i=0; i<sizeof(payload); i++){
                printf("%02X ",payload[i]);
            }
        }
        else{
            printf("there is no data\n");
        }


        printf("\n\n==============================\n");

    }
    else{
        printf("not tcp packet\n");
        printf("\n==============================\n");
        return;
    }

}




bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}


        printf("\n%u bytes captured\n\n", header->caplen);
        packet_parsing(packet,header->caplen);
	}

	pcap_close(pcap);
}
