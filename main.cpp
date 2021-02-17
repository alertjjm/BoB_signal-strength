#include <stdio.h>
#include <pcap.h>
#include <stdint.h>
#include <iostream>
#include<string>
#include "header.h"
#include "mac.h"
using namespace std;

void usage() {
    printf("syntax: signal-strength <interface> <target AP MAC>\n");
    printf("sample: signal-strength wlan1 11:22:33:44:55:66\n");
}
void show_pckt_info(pcap_t* handle,Mac targetmac){
    struct pcap_pkthdr* header;
    const u_char* packet;
    u_int size_ip,size_tcp,size_payload; //size of the headers and payload
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) return;
    if (res == -1 || res == -2) {
        printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
        exit(1);
    }
    radiotap_header* rt_header=(radiotap_header*)packet;
    ieeeheader* i_header=(ieeeheader*)(packet+rt_header->length);
    short typesubtype=i_header->type_subtype & 0B00001100;
    //http://80211notes.blogspot.com/2013/09/understanding-address-fields-in-80211.html
    if(typesubtype==0B00001000){//managed
        if(i_header->addr3==targetmac)
            printf("%d\t station: [Sen]%s  [Tran]%s  [Rec]%s  [Des]%s  [MANAGED]\n",rt_header->antenna_signal-256,string(i_header->addr2).c_str(),string(i_header->addr2).c_str(),string(i_header->addr1).c_str(),string(i_header->addr1).c_str());
    }
    else if(typesubtype==0B00000000){//data()
        if(i_header->addr2==targetmac)
            printf("%d\t station: [Sen]%s  [Tran]%s  [Rec]%s  [Des]%s  [DATA]\n",rt_header->antenna_signal-256,string(i_header->addr3).c_str(),string(i_header->addr2).c_str(),string(i_header->addr1).c_str(),string(i_header->addr1).c_str());
    }
    else{
        //printf("control\n");
        //has no bssid in frame
    }
}
int main(int argc, char* argv[]) {
    if (argc != 3) {
        usage();
        return -1;
    }
    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    Mac targetmac(argv[2]);
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
        return -1;
    }
    while (true) {
        show_pckt_info(handle,targetmac);
    }
    pcap_close(handle);
}
