#ifndef COMMON_H
#define COMMON_H


#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif


#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif


#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <stdint.h>


#define TCP_PORT 8080
#define UDP_PORT 8081

#define BUFFER_SIZE 1024

#define CHANNEL_BANDWIDTH 1000000.0

// HIZ AYARLARI
#define RUNS 3
#define MAX_CLIENTS 5

#define ACK_TIMEOUT_MS 60
#define MAX_RETRY 3  // dusuk SNR'da sans artsin


#define TCP_TIMEOUT_MS 300
#define UDP_TIMEOUT_MS 300

//Mesaj türleri
#define MSG_REQUEST 1
#define MSG_DATA    2
#define MSG_END     3
#define MSG_ACK     4
#define MSG_REPAIR  5

#pragma pack(push, 1)
typedef struct {
    int MessageType;
    int SequenceNumber;
    int DataLength;
    double SnrDb;
    unsigned long Checksum;
    char FileName[150];
    char Data[BUFFER_SIZE];
} Packet;
#pragma pack(pop)

typedef struct {
    long TotalBytes;
    int TotalPackets;
    int LostPackets;
    double LossPercent;
    int CorruptedPackets;
    int RepairedPackets;
    double TransferTimeSec;
    double ThroughputBps;   //client'ta Goodput olarak raporlanacak
    int PacketSize;
} Stats;


extern volatile LONG gClientCount;


unsigned long calculate_checksum(const char *data, int len);

void run_server(void);
void run_client(void);

#endif
