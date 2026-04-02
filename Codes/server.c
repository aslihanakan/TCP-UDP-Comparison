#include "common.h"
#include "channel.h"

volatile LONG gClientCount = 0; //ayný anda kaç kiþinin TCP den baðlandýðýný sayýyo

//TCP için belirlenen sürede veri gelmezse beklemeyi býrakmasýný söylüyo
static void set_tcp_timeouts(SOCKET sock)
{
    DWORD tv = (DWORD)TCP_TIMEOUT_MS;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, (int)sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, (int)sizeof(tv));
}

//UDP de gönderdiði paketin geldiðini anlamak için sonsuza kadar ACK beklmesin diye
static void set_udp_timeouts_ack(SOCKET sock)
{
    DWORD tv = (DWORD)ACK_TIMEOUT_MS;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, (int)sizeof(tv));
}

//TCP için gönderilen paketin tamamýnýn alýnmasý için len byte tamamlanana kadar okur
static int recv_all(SOCKET s, char *buf, int len)
{
    int got, total = 0;
    while (total < len) {
        got = recv(s, buf + total, len - total, 0);
        if (got <= 0) return got;
        total += got;
    }
    return total;
}

//TCP'nin,peketlerin tamamýný len byte bitene kadar yollamaya devam etmesi için
static int send_all(SOCKET s, const char *buf, int len)
{
    int sent, total = 0;
    while (total < len) {
        sent = send(s, buf + total, len - total, 0);
        if (sent <= 0) return sent;
        total += sent;
    }
    return total;
}

//Clientteki paket toplamýyla burdakini karþýlaþtýrýp ayný deðilse bozuk der -bozukluk kontrolü-
unsigned long calculate_checksum(const char *data, int len)
{
    unsigned long sum = 0;
    int i;
    for (i = 0; i < len; i++) sum += (unsigned char)data[i];
    return sum;
}

//Baðlanan clientin IP ve PORT unu ekrana yazdýrýyor
static void print_peer_inline(const struct sockaddr_in *a)
{
    const char *ip;
    unsigned short port;

    if (!a) { printf("?:?\n"); return; }
    ip = inet_ntoa(a->sin_addr);
    port = ntohs(a->sin_port);
    if (!ip) ip = "?";
    printf("%s:%u\n", ip, (unsigned)port);
}

//TCP ile gelen her client için ayrý çalýþýyor
static DWORD WINAPI tcp_client_thread(LPVOID arg)
{
    SOCKET s;
    SOCKET *ps;

    Packet req, pkt_clean, pkt_send, resp;
    FILE *fp;
    int seq, got, ok, tries, repaired_wait_tries;

    struct sockaddr_in peer;
    int peerLen;

    int totalSentPackets;
    int totalRepairReq;
    long totalBytes;

    ps = (SOCKET*)arg; //ps socketin adresini tutan pointer
    s = *ps;//programda kullanýlacak gerçek socket
    free(ps);

    set_tcp_timeouts(s);//zaman durumunu kontrol eder programýn durmuþ gibi gözükmesini engeller

    memset(&peer, 0, sizeof(peer));
    peerLen = (int)sizeof(peer);
    getpeername(s, (struct sockaddr*)&peer, &peerLen);//Hangi client baðlandý nerden baðlandý bigisini tutup sonra çýktýlarda vermek için

    memset(&req, 0, sizeof(req));
    got = recv_all(s, (char*)&req, (int)sizeof(req));
    if (got <= 0 || req.MessageType != MSG_REQUEST) { //Clientten dosya adý ve snr deðeri içeren mesajý bekliyo
        closesocket(s);
        InterlockedDecrement(&gClientCount);
        return 0;
    }

    printf("[TCP] Request: file='%s' snr=%.1f dB | client ", req.FileName, req.SnrDb);
    print_peer_inline(&peer);

    fp = fopen(req.FileName, "rb");
    if (!fp) {
        printf("[TCP] Error: Could not open file '%s'\n", req.FileName);

        memset(&resp, 0, sizeof(resp));
        resp.MessageType = MSG_END;
        send_all(s, (char*)&resp, (int)sizeof(resp));

        closesocket(s);
        InterlockedDecrement(&gClientCount);
        return 0;
    }

    totalSentPackets = 0;
    totalRepairReq = 0;
    totalBytes = 0;


    //Dosyayý paket paket gönderme aþamasý
    seq = 0;
    while (1) {
        memset(&pkt_clean, 0, sizeof(pkt_clean));
        pkt_clean.DataLength = (int)fread(pkt_clean.Data, 1, BUFFER_SIZE, fp);
        if (pkt_clean.DataLength <= 0) break;

        pkt_clean.MessageType = MSG_DATA;
        pkt_clean.SequenceNumber = seq;//Dosyanýn kaçýncý parçasýný gönderdiðinin bilgisi
        pkt_clean.SnrDb = req.SnrDb;
        pkt_clean.Checksum = calculate_checksum(pkt_clean.Data, pkt_clean.DataLength);//cliente karþýlaþtýrma için verilecek checksum hesap sonucu

        ok = 0;
        tries = 0;


        //ACK-REPAIR=Client gönderdiðimiz paketi client saðlam aldým diyene kadar tekrar yollama
        while (!ok) {
            if (tries >= MAX_RETRY) {
                fclose(fp);
                closesocket(s);
                InterlockedDecrement(&gClientCount);
                return 0;
            }

            pkt_send = pkt_clean; //client bozuk derse serverýn tekrar göndermek için temiz veriyi kopyalýyo
            apply_noise(pkt_send.Data, pkt_send.DataLength, req.SnrDb); //verdiðimiz snr deðerine göre dosyayý bozduðumuz yer

            if (send_all(s, (char*)&pkt_send, (int)sizeof(pkt_send)) <= 0){  //seerver clienta tam paket yapýsýný gönderiyor
                fclose(fp);
                closesocket(s);
                InterlockedDecrement(&gClientCount);
                return 0;
            }

            memset(&resp, 0, sizeof(resp));
            got = recv_all(s, (char*)&resp, (int)sizeof(resp));//clientten yanýt bekliyo
            if (got <= 0) { tries++; continue; }


            //ACK= bu parçayý saðlam aldým mesajý gelir iþlem sýradakine geçer
            if (resp.MessageType == MSG_ACK && resp.SequenceNumber == seq) {
                ok = 1;

                //Reapir = Bozuk geldi temzini gönder dendiðinde tekrar temiz parçayý gönderir
            } else if (resp.MessageType == MSG_REPAIR && resp.SequenceNumber == seq) {

                totalRepairReq++;

                if (send_all(s, (char*)&pkt_clean, (int)sizeof(pkt_clean)) <= 0) {
                    fclose(fp);
                    closesocket(s);
                    InterlockedDecrement(&gClientCount);
                    return 0;
                }

                repaired_wait_tries = 0;
                while (1) {
                    if (repaired_wait_tries >= MAX_RETRY) {
                        fclose(fp);
                        closesocket(s);
                        InterlockedDecrement(&gClientCount);
                        return 0;
                    }

                    memset(&resp, 0, sizeof(resp));
                    got = recv_all(s, (char*)&resp, (int)sizeof(resp));
                    if (got <= 0) { repaired_wait_tries++; continue; }

                    if (resp.MessageType == MSG_ACK && resp.SequenceNumber == seq) {
                        ok = 1;
                        break;
                    }
                    repaired_wait_tries++;
                }
            } else {
                tries++;
            }
        }

        //Bu parça bitti sýradakine geç
        totalSentPackets++;
        totalBytes += pkt_clean.DataLength;
        seq++;
    }

    memset(&resp, 0, sizeof(resp));
    resp.MessageType = MSG_END;
    send_all(s, (char*)&resp, (int)sizeof(resp));

    printf("[TCP] Done: bytes=%ld packets=%d repairs=%d\n",
           totalBytes, totalSentPackets, totalRepairReq);

    fclose(fp);
    closesocket(s);
    InterlockedDecrement(&gClientCount);//Clientler ayný anda baðlandýðýnda yanlýþ saymamak için bu fonksiyonu kullandým
    return 0;
}

//UDP de thread yok server tek socket üzerinden istek alýyo
static void udp_transfer_once(SOCKET us, struct sockaddr_in *cli, int cliLen,
                              const char *fileName, double snrDb)
{
    FILE *fp;
    Packet pkt_clean, pkt_send, resp;
    int seq, got, ok, tries;
    struct sockaddr_in from;
    int fromLen;

    int totalSentPackets;
    int totalRepairReq;
    int totalDrops;
    long totalBytes;

    printf("[UDP] Request: file='%s' snr=%.1f dB | client ", fileName, snrDb);
    print_peer_inline(cli);

    fp = fopen(fileName, "rb");
    if (!fp) {
        printf("[UDP] Error: Could not open file '%s'\n", fileName);

        memset(&resp, 0, sizeof(resp));
        resp.MessageType = MSG_END;
        sendto(us, (char*)&resp, (int)sizeof(resp), 0, (struct sockaddr*)cli, cliLen);
        return;
    }

    set_udp_timeouts_ack(us);//sonsuza kadar beklemesin diye

    //Sayaçlar
    totalSentPackets = 0;
    totalRepairReq = 0;
    totalDrops = 0;
    totalBytes = 0;

    //dosyadan parça parça okunuyo
    seq = 0;
    while (1) {
        memset(&pkt_clean, 0, sizeof(pkt_clean));
        pkt_clean.DataLength = (int)fread(pkt_clean.Data, 1, BUFFER_SIZE, fp);
        if (pkt_clean.DataLength <= 0) break;

        //paket hazýrlama
        pkt_clean.MessageType = MSG_DATA;
        pkt_clean.SequenceNumber = seq;
        pkt_clean.SnrDb = snrDb;
        pkt_clean.Checksum = calculate_checksum(pkt_clean.Data, pkt_clean.DataLength);

        ok = 0;
        tries = 0;

        while (!ok) {
            if (tries >= MAX_RETRY) break;

            //Gerçek sistemlerdeki UDP davranýþýný simüle etmek için SNR deðeri düþük olduðunda bazý pakeetleri drop eder
            if (should_drop_packet(pkt_clean.DataLength, snrDb)) {
                totalDrops++;
                tries++;
                continue;
            }

            pkt_send = pkt_clean;//önce temiz dosya kopyalanýyor sonra bilerek bozulup yollanýyor
            apply_noise(pkt_send.Data, pkt_send.DataLength, snrDb);

            sendto(us, (char*)&pkt_send, (int)sizeof(pkt_send), 0, (struct sockaddr*)cli, cliLen);

            memset(&resp, 0, sizeof(resp));
            fromLen = (int)sizeof(from);
            got = recvfrom(us, (char*)&resp, (int)sizeof(resp), 0, (struct sockaddr*)&from, &fromLen);

            //birkaç client ayný anda mesaj yolladýðýnda hangisinin olduðuna bakma
            if (got > 0 &&
                from.sin_addr.s_addr == cli->sin_addr.s_addr && from.sin_port == cli->sin_port) {

                //ACK yani doya düzgün
                if (resp.MessageType == MSG_ACK && resp.SequenceNumber == seq) {
                    ok = 1;
                }
                else if (resp.MessageType == MSG_REPAIR && resp.SequenceNumber == seq) {

                    totalRepairReq++;

                   //Reapir yani kopyaladýðý temiz veriden gönderim yapma
                    sendto(us, (char*)&pkt_clean, (int)sizeof(pkt_clean), 0, (struct sockaddr*)cli, cliLen);

                    memset(&resp, 0, sizeof(resp));
                    fromLen = (int)sizeof(from);
                    got = recvfrom(us, (char*)&resp, (int)sizeof(resp), 0, (struct sockaddr*)&from, &fromLen);

                    //doðru parça doðruu cliente gönderildi mi
                    if (got > 0 &&
                        from.sin_addr.s_addr == cli->sin_addr.s_addr && from.sin_port == cli->sin_port &&
                        resp.MessageType == MSG_ACK && resp.SequenceNumber == seq) {
                        ok = 1;
                    }
                }
            }

            tries++;
        }

        totalSentPackets++;
        totalBytes += pkt_clean.DataLength;
        seq++;
    }

    memset(&resp, 0, sizeof(resp));
    resp.MessageType = MSG_END;
    sendto(us, (char*)&resp, (int)sizeof(resp), 0, (struct sockaddr*)cli, cliLen);//dosya gönderimi bitti

    printf("[UDP] Done: bytes=%ld packets=%d repairs=%d drops=%d\n",
           totalBytes, totalSentPackets, totalRepairReq, totalDrops);

    fclose(fp);
}

void run_server(void)
{
    SOCKET ts, us;
    struct sockaddr_in addr, cli;
    int cliLen;

    SOCKET cs;
    HANDLE th;
    DWORD tid;

    Packet req;
    int got;


    srand((unsigned)time(NULL));

    //TCP için socket açýyor
    ts = socket(AF_INET, SOCK_STREAM, 0);
    if (ts == INVALID_SOCKET) { printf("TCP socket() failed.\n"); return; }

    //TCP adres bilgileri
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(TCP_PORT);

    if (bind(ts, (struct sockaddr*)&addr, (int)sizeof(addr)) == SOCKET_ERROR) {//TCP threadi porta baðlama
        printf("TCP bind() failed.\n");
        closesocket(ts);
        return;
    }

    if (listen(ts, 10) == SOCKET_ERROR) {
        printf("listen() failed.\n");
        closesocket(ts);
        return;
    }

    //UDP socket açma
    us = socket(AF_INET, SOCK_DGRAM, 0);
    if (us == INVALID_SOCKET) {
        printf("UDP socket() failed.\n");
        closesocket(ts);
        return;
    }

    addr.sin_port = htons(UDP_PORT);
    if (bind(us, (struct sockaddr*)&addr, (int)sizeof(addr)) == SOCKET_ERROR) {
        printf("UDP bind() failed.\n");
        closesocket(us);
        closesocket(ts);
        return;
    }

    printf("Server running...\n");
    printf("TCP: %d (timeout=%dms)  UDP: %d (ack-timeout=%dms)\n\n",
           TCP_PORT, TCP_TIMEOUT_MS, UDP_PORT, ACK_TIMEOUT_MS);

    while (1) {
        fd_set rfds;
        struct timeval tv;
        int maxfd, sel;

        FD_ZERO(&rfds);
        //hem TCP hem UDP ye ayný anda bakýyo
        FD_SET(ts, &rfds);
        FD_SET(us, &rfds);

        maxfd = (int)((ts > us) ? ts : us);
        tv.tv_sec = 0;
        tv.tv_usec = 200000;

        sel = select(maxfd + 1, &rfds, NULL, NULL, &tv);
        if (sel <= 0) continue;

        //TCP istendiyse accept + thread
        if (FD_ISSET(ts, &rfds)) {
            cliLen = (int)sizeof(cli);
            cs = accept(ts, (struct sockaddr*)&cli, &cliLen);
            if (cs != INVALID_SOCKET) {
                    //max client sayýsýný kontrol etme
                if (InterlockedIncrement(&gClientCount) > MAX_CLIENTS) {
                    InterlockedDecrement(&gClientCount);
                    closesocket(cs);
                } else {//thread açma kýsmý
                    SOCKET *ps = (SOCKET*)malloc(sizeof(SOCKET));
                    if (!ps) {
                        closesocket(cs);
                        InterlockedDecrement(&gClientCount);
                    } else {
                        *ps = cs;
                        th = CreateThread(NULL, 0, tcp_client_thread, (LPVOID)ps, 0, &tid);
                        if (th) CloseHandle(th);
                        else {
                            free(ps);
                            closesocket(cs);
                            InterlockedDecrement(&gClientCount);
                        }
                    }
                }
            }
        }

        //UDP istendiyse recvfrom + resquest ise dosya gönder
        if (FD_ISSET(us, &rfds)) {
            memset(&req, 0, sizeof(req));
            cliLen = (int)sizeof(cli);
            got = recvfrom(us, (char*)&req, (int)sizeof(req), 0, (struct sockaddr*)&cli, &cliLen);

            if (got > 0 && req.MessageType == MSG_REQUEST) {
                udp_transfer_once(us, &cli, cliLen, req.FileName, req.SnrDb);
            }
        }
    }
}

