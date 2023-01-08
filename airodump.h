//
// Created by onedayginger on 07/01/23.
//
#include <pcap.h>
#include <cstdlib>

#ifndef AIRODUMP_AIRODUMP_H
#define AIRODUMP_AIRODUMP_H
#define FIXED_PARAM_LEN 12

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

class Airodump {
private:
    char* device_;
    char errbuf_[PCAP_ERRBUF_SIZE];
    pcap_t* handle_;

    int current_packet_length;
    int packet_length_left;

public:
    // constructor and destructor
    Airodump(char* device);
    ~Airodump();;

    void monitor();
    int captureBeaconFrame(const u_char* packet);
    void parseManagementFrame(const u_char* packet);
};


#endif //AIRODUMP_AIRODUMP_H
