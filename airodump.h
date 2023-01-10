//
// Created by onedayginger on 07/01/23.
//
#include <pcap.h>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <iomanip>
#include <vector>

#ifndef AIRODUMP_AIRODUMP_H
#define AIRODUMP_AIRODUMP_H
#define FIXED_PARAM_LEN 12
#define MAC_LEN 6

using namespace std;

struct ieee80211_radiotap_header {
    u_int8_t        it_version;     /* set to 0 */
    u_int8_t        it_pad;
    u_int16_t       it_len;         /* entire length */
    u_int32_t       it_present;     /* fields present */
} __attribute__((__packed__));

struct beacon_frame {
    u_int16_t       frame_control;
    u_int16_t       duration;
    u_int8_t        destination_addr[6];
    u_int8_t        source_addr[6];
    u_int8_t        bssid[6];
    u_int16_t       sequence_control;
} __attribute__((__packed__));

enum ManagementTag {
    SSID = 0x00,
    CHANNEL = 0x03
};

struct AP {
    u_int8_t    BSSID[6];
    int         beacons;
    char       ESSID[30];
} __attribute__((__packed__));

class Airodump {
private:
    char* device_;
    char errbuf_[PCAP_ERRBUF_SIZE];
    pcap_t* handle_;

    int current_packet_length;
    int packet_length_left;

    vector<AP> AP_vector;

public:
    // constructor and destructor
    Airodump(char* device);
    ~Airodump();

    void monitor();
    void captureBeaconFrame(const u_char* packet, int packet_len);
    void parseManagementFrame(AP* target_AP, const u_char* packet);
    void drawTable();
    AP* checkVectorList(const u_int8_t* BSSID);
};


#endif //AIRODUMP_AIRODUMP_H
