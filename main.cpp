//
// Created by onedayginger on 07/01/23.
//

#include <cstdio>
#include <pcap.h>
#include "airodump.h"

void usage() {
    printf("syntax: airodump <interface>\n");
    printf("sample: airodump mon0\n");
}

int main(int argc, char* argv[]) {

    if (argc < 2) {
        usage() ;
        return -1;
    }

    Airodump airodumper(argv[1]);
    airodumper.monitor();

}