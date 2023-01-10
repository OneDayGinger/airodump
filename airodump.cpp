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

    printf("%-19s %-15s %-30s\n", "BSSID", "beacons", "ESSID");

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
        Airodump::captureBeaconFrame(packet, header->caplen);
    }
}

void Airodump::captureBeaconFrame(const u_char* packet, int packet_len) {

    ieee80211_radiotap_header* irh = (ieee80211_radiotap_header *)packet;
    beacon_frame* bf = (beacon_frame *)(packet + irh->it_len);

    if (bf->frame_control != 0x0080) return;

    current_packet_length = packet_len;
    packet_length_left = packet_len - (irh->it_len + sizeof(*bf));
    AP* existing_AP = Airodump::checkVectorList(bf->bssid);
    if (existing_AP) {
        current_packet_length = packet_len;
        packet_length_left = packet_len - (irh->it_len + sizeof(*bf));
        Airodump::parseManagementFrame(existing_AP, packet);
    }
    Airodump::drawTable();
    /*
    else {
        // print BSSID
        for (int i=0; i<MAC_LEN; i++) {
            printf("%02X", bf->bssid[i]);
            if (i!=5) printf(":");
            else printf("   ");
        }

        return irh->it_len + sizeof(*bf);
    }
     */
}

AP* Airodump::checkVectorList(const u_int8_t* BSSID) {
    vector<AP>::iterator iter;
    for(iter=AP_vector.begin(); iter!=AP_vector.end(); iter++) {
        if (memcmp(iter->BSSID, BSSID, 6)==0) {
            iter->beacons += 1;
            return nullptr;
        }
    }
    printf("NEW AP\n");
    AP* new_AP = new AP;
    memcpy(new_AP->BSSID, BSSID, 6);
    AP_vector.push_back(*new_AP);
    return new_AP;
}

void Airodump::parseManagementFrame(AP* target_AP, const u_char* packet) {
    packet_length_left -= FIXED_PARAM_LEN;
    int readlen;

    struct tag_header {
        u_int8_t tag_number;
        u_int8_t tag_length;
    };

    while (packet_length_left > 0) {
        readlen = current_packet_length - packet_length_left;
        tag_header *th = (tag_header *) (packet + readlen);

        if (th->tag_number == SSID) {
            char* essid = (char*)malloc(th->tag_length + 1);
            for (int i = 0; i < th->tag_length and i < 30; i++) {
                essid[i] = *(packet + readlen + 2 + i);
                printf("%c", essid[i]);
            }
            if (th->tag_length < 30) {
                essid[th->tag_length] = 0x00;
                printf("\n");
            }
            else essid[29] = 0x00;
            memcpy(target_AP->ESSID, &essid[0], sizeof(essid));
            for (int i = 0; i < th->tag_length and i < 30; i++) {
                printf("%c", target_AP->ESSID[i]);
            }
        }

        packet_length_left -= sizeof(tag_header) + th->tag_length;
    }
}

void Airodump::drawTable() {
    vector<AP>::iterator iter;
    for(iter=AP_vector.begin(); iter!=AP_vector.end(); iter++) {
        // print BSSID
        for(int i=0; i<MAC_LEN; i++){
            printf("%02X", iter->BSSID[i]);
            if (i<MAC_LEN-1) {
                printf(":");
            }
            else {
                printf("   ");
            }
        }

        // print beacons
        printf("%-15d ", iter->beacons);

        // print ESSID
        for (int i = 0; i < 30; i++) {
            printf("%02X", (iter->ESSID)[i]);
        }
        printf("\n");

    }
}


