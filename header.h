#pragma once
#include <stdlib.h>
#include <arpa/inet.h>
#include <string>
#include<iostream>
#include "mac.h"
using namespace std;
#pragma pack(push, 1)
typedef struct radiotap_header {
        uint8_t        revision; 
        uint8_t        pad;
        uint16_t       length;    
        uint64_t       present_flags;    
        uint8_t        flags;
        uint8_t        data_Rate;
        uint16_t       channel_frequency;
        uint16_t       channel_flags;
        uint8_t        antenna_signal;
        uint8_t        dummy;   
        uint16_t       RX_flags;
        uint8_t        antenna_signal2;
        uint8_t        antenna;
}radiotap_header;
#pragma pack(pop)
#pragma pack(push, 1)
typedef struct ieeeheader{
        uint8_t        type_subtype; //8
        uint8_t        flag;    //00
        uint16_t       duration; //0
        Mac            addr1;
        Mac            addr2;
        Mac            addr3;
        uint16_t       fragment_snum;
        uint16_t       fixed_parameters[6];
}ieeeheader;
#pragma pack(pop)