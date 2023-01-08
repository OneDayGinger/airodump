//
// Created by onedayginger on 07/01/23.
//

#include "airodump.h"

// constructor
Airodump::Airodump(char* device) : device_(device){
    printf("Airodump::Airodump(char* device)\n");
    handle_ = pcap_open_live(device_, BUFSIZ, 1, 1000, errbuf_);
}

// destructor
Airodump::~Airodump() {

}

void Airodump::monitor() {
    printf("Airodump::monitor()\n");
    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle_, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle_));
            break;
        }

        // check if the packet is beacon frame
        res = Airodump::captureBeaconFrame(packet);
        if (res==-1) continue;
        current_packet_length = header->len;
        packet_length_left = header->len - res;


        // parse beacon frame
        Airodump::parseManagementFrame(packet);
    }
}

int Airodump::captureBeaconFrame(const u_char* packet) {
    ieee80211_radiotap_header* irh = (ieee80211_radiotap_header *)packet;
    beacon_frame* bf = (beacon_frame *)(packet + irh->it_len);

    if (bf->frame_control != 0x0080) return -1;
    else {
        return irh->it_len + sizeof(*bf);
    }
}

void Airodump::parseManagementFrame(const u_char* packet) {
    packet_length_left -= FIXED_PARAM_LEN;
    int readlen;

    struct tag_header {
        u_int8_t tag_number;
        u_int8_t tag_length;
    };

    while(packet_length_left>0){
        readlen = current_packet_length - packet_length_left;
        tag_header* th = (tag_header*)(packet + readlen);

        if (th->tag_number==SSID) {
            printf("SSID: ");
            for (int i=0; i<th->tag_length; i++) {
                printf("%c", *(packet + readlen + 2 + i));
            }
            printf("\n");
        }

        packet_length_left -= sizeof(tag_header) + th->tag_length;\
    }

}


