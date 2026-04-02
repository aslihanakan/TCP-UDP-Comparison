#include "common.h"
#include "channel.h"

//Tasmadan yazi kopyalar
static void safe_strcpy(char *dst, int dstSize, const char *src)
{
    int i;
    if (!dst || dstSize <= 0) return;
    if (!src) { dst[0] = '\0'; return; }
    for (i = 0; i < dstSize - 1 && src[i] != '\0'; i++) dst[i] = src[i];
    dst[i] = '\0';
}

static void safe_strcat(char *dst, int dstSize, const char *src)
{
    int dlen, i;
    if (!dst || dstSize <= 0) return;
    if (!src) return;
    dlen = (int)strlen(dst);
    if (dlen >= dstSize - 1) return;
    for (i = 0; dlen + i < dstSize - 1 && src[i] != '\0'; i++) dst[dlen + i] = src[i];
    dst[dlen + i] = '\0';
}

static void safe_strncat_len(char *dst, int dstSize, const char *src, int srcLen)
{
    int dlen, i;
    if (!dst || dstSize <= 0) return;
    if (!src || srcLen <= 0) return;
    dlen = (int)strlen(dst);
    if (dlen >= dstSize - 1) return;
    for (i = 0; i < srcLen && dlen + i < dstSize - 1; i++) dst[dlen + i] = src[i];
    dst[dlen + i] = '\0';
}

//Gönderim yarim olmasin diye parça parça gönderip tamami gidene kadar tekrar eder
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

//Alýrken eksik gelmesin
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

//Hassas zaman ölçümü
static double now_sec(void)
{
    static LARGE_INTEGER freq;
    LARGE_INTEGER t;
    if (freq.QuadPart == 0) QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t);
    return (double)t.QuadPart / (double)freq.QuadPart;
}

//Yeni bir çýktý dosyasý adý oluþturmak için
static void make_out_name(char *out, int outSize, const char *prefix, const char *file)
{
    const char *p;

    if (!out || outSize <= 0) return;
    out[0] = '\0';

    if (!prefix) prefix = "";
    if (!file) file = "";

    p = strrchr(file, '\\');
    if (!p) p = strrchr(file, '/');
    if (!p) p = file;
    else p++;

    safe_strcpy(out, outSize, prefix);
    safe_strcat(out, outSize, p);
}

static void append_snr_tag(char *out, int outSize, double snrDb)
{
    char tag[64], num[32];
    char *dot;
    int snrInt;

    if (!out || outSize <= 0) return;

    snrInt = (int)(snrDb >= 0 ? (snrDb + 0.5) : (snrDb - 0.5));

    tag[0] = '\0';
    safe_strcpy(tag, (int)sizeof(tag), "_snr");
    sprintf(num, "%d", snrInt);
    safe_strcat(tag, (int)sizeof(tag), num);

    dot = strrchr(out, '.');
    if (dot) {
        char newOut[512];
        int baseLen = (int)(dot - out);
        if (baseLen < 0) baseLen = 0;

        newOut[0] = '\0';
        safe_strncat_len(newOut, (int)sizeof(newOut), out, baseLen);
        safe_strcat(newOut, (int)sizeof(newOut), tag);
        safe_strcat(newOut, (int)sizeof(newOut), dot);
        safe_strcpy(out, outSize, newOut);
    } else {
        safe_strcat(out, outSize, tag);
    }
}


//TCP ile gönderim sýrasýnda veri gelmezse veya gönderilmezse takýlý kalmayý engelliyor
static void set_tcp_timeouts(SOCKET sock)
{
    DWORD tv = (DWORD)TCP_TIMEOUT_MS;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, (int)sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, (int)sizeof(tv));
}
//UDP de paket gönderirken cevap gelmezse bir süre sonra beklemeyi býrakýyor
static void set_udp_timeouts(SOCKET sock)
{
    DWORD tv = (DWORD)UDP_TIMEOUT_MS;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, (int)sizeof(tv));
}

//Her test sonrasý sonuçlarý baþka bir dosyaya kaydediyor
static void append_results_csv(double snr, double berTh,
                               const char *protocol,
                               double timeSec,
                               double lossPct,
                               double corruptPct,
                               double goodputMbps,
                               double shannonMbps,
                               double successPct)
{
    FILE *csv = fopen("results.csv", "a");
    if (!csv) return;

    fseek(csv, 0, SEEK_END);
    if (ftell(csv) == 0) {
        fprintf(csv, "SNR,BER_Theory,Protocol,Time_s,Loss_Pct,Corrupt_Pct,Goodput_Mbps,Shannon_Mbps,Success_Pct\n");
    }

    fprintf(csv, "%.0f,%.3e,%s,%.2f,%.1f,%.2f,%.2f,%.2f,%.1f\n",
            snr, berTh, protocol, timeSec, lossPct, corruptPct, goodputMbps, shannonMbps, successPct);

    fclose(csv);
}

//TCP nin dosya alýþveriþ süreci
static Stats tcp_receive_once(const char *ip, const char *file, double snr, const char *saveName)
{
    Stats s;
    SOCKET sock;
    struct sockaddr_in srv;
    Packet req, pkt, resp;
    FILE *fp;
    double t0, t1;
    long totalBytes;
    int totalPackets;
    int corrupted, repaired;
    int got;
    unsigned long cs;

    //Baþlangýçta paket sonuçlarý sýfýrlanýyor
    memset(&s, 0, sizeof(s));
    s.PacketSize = BUFFER_SIZE;

    //TCP baðlantýsý açýyor
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) return s;

    set_tcp_timeouts(sock);//Baðlantýda sorun olursa program sonsuza kadar beklemesin


    //Server adresini hazýrlayýp baðlanýyor
    memset(&srv, 0, sizeof(srv));
    srv.sin_family = AF_INET;
    srv.sin_port = htons(TCP_PORT);
    srv.sin_addr.s_addr = inet_addr(ip);
    if (srv.sin_addr.s_addr == INADDR_NONE) {
        closesocket(sock);
        return s;
    }

    if (connect(sock, (struct sockaddr*)&srv, (int)sizeof(srv)) == SOCKET_ERROR) {
        closesocket(sock);
        return s;
    }


    //Servera dosya istiyorum mesajýný gönderiyor
    memset(&req, 0, sizeof(req));
    req.MessageType = MSG_REQUEST;
    req.SnrDb = snr;
    strncpy(req.FileName, file ? file : "", sizeof(req.FileName) - 1);
    req.FileName[sizeof(req.FileName) - 1] = '\0';

    if (send_all(sock, (const char*)&req, (int)sizeof(req)) <= 0) {
        closesocket(sock);
        return s;
    }

    fp = fopen(saveName, "wb");
    if (!fp) {
        closesocket(sock);
        return s;
    }

    totalBytes = 0;
    totalPackets = 0;
    corrupted = 0;
    repaired = 0;

    t0 = now_sec();//Ölçümleri baþlatýyor

    //Paket al- Kontrol et- yaz
    while (1) {
        memset(&pkt, 0, sizeof(pkt));
        got = recv_all(sock, (char*)&pkt, (int)sizeof(pkt));
        if (got <= 0) break;

        if (pkt.MessageType == MSG_END) break;

        //Gelen veri paketinin uzunluðunu uygun olup olmadýðýný kotrol ediyo
        if (pkt.MessageType == MSG_DATA) {
            if (pkt.DataLength < 0 || pkt.DataLength > BUFFER_SIZE) break;

            //Paketin bozulup bozulmadýðýný kontrol ediyor
            cs = calculate_checksum(pkt.Data, pkt.DataLength);

            if (cs != pkt.Checksum) {
                corrupted++;//bozuksa corrupet artýrýlýyo

                memset(&resp, 0, sizeof(resp));
                resp.MessageType = MSG_REPAIR; //Bozuksa tekrar istiyor
                resp.SequenceNumber = pkt.SequenceNumber;

                if (send_all(sock, (const char*)&resp, (int)sizeof(resp)) <= 0) break;

                memset(&pkt, 0, sizeof(pkt));
                got = recv_all(sock, (char*)&pkt, (int)sizeof(pkt));//Sonra tekrar paketi alýyor
                if (got <= 0) break;

                if (pkt.DataLength < 0 || pkt.DataLength > BUFFER_SIZE) break;
                cs = calculate_checksum(pkt.Data, pkt.DataLength);

                if (cs != pkt.Checksum) {
                    corrupted++;
                    break;
                }

                repaired++;//bozuk deðilse artar
            }

            //Aldým diye mesaj yollar
            memset(&resp, 0, sizeof(resp));
            resp.MessageType = MSG_ACK;
            resp.SequenceNumber = pkt.SequenceNumber;

            if (send_all(sock, (const char*)&resp, (int)sizeof(resp)) <= 0) break;

            fwrite(pkt.Data, 1, (size_t)pkt.DataLength, fp);
            totalBytes += pkt.DataLength;
            totalPackets++;
        }
    }

    t1 = now_sec();

    fclose(fp);
    closesocket(sock);

    s.TotalBytes = totalBytes;
    s.TotalPackets = totalPackets;
    s.CorruptedPackets = corrupted;
    s.RepairedPackets = repaired;
    s.TransferTimeSec = (t1 - t0);//Toplam transfer süresi

    if (s.TransferTimeSec > 0.0) {
        //Toplam gelen veri : geçen süre= hýz hesabý
        s.ThroughputBps = ((double)s.TotalBytes * 8.0) / s.TransferTimeSec;
    }

    //TCP de kayýp olmaz
    s.LostPackets = 0;
    s.LossPercent = 0.0;

    return s;
}

//UDP nin dosya alýþveriþ süreci
static Stats udp_receive_once(const char *ip, const char *file, double snr, const char *saveName)
{
    Stats s;
    SOCKET sock;
    struct sockaddr_in srv, peer;
    int havePeer;

    Packet req, pkt, resp;
    FILE *fp;
    double t0, t1;
    long totalBytes;
    int totalPackets, corrupted, repaired, lossEvents, expectedSeq;
    int got, fromLen;
    unsigned long cs;

    int tries, skip_current, reqTries;

    (void)file;

    memset(&s, 0, sizeof(s));
    s.PacketSize = BUFFER_SIZE;

    sock = socket(AF_INET, SOCK_DGRAM, 0); //UDP socketini açar ve server adresini ayarlýyor
    if (sock == INVALID_SOCKET) return s;

    memset(&srv, 0, sizeof(srv));
    srv.sin_family = AF_INET;
    srv.sin_port = htons(UDP_PORT);
    srv.sin_addr.s_addr = inet_addr(ip);
    if (srv.sin_addr.s_addr == INADDR_NONE) {
        closesocket(sock);
        return s;
    }

    set_udp_timeouts(sock);

    memset(&req, 0, sizeof(req));
    req.MessageType = MSG_REQUEST;
    req.SnrDb = snr;
    strncpy(req.FileName, file ? file : "", sizeof(req.FileName) - 1);
    req.FileName[sizeof(req.FileName) - 1] = '\0';

    sendto(sock, (char*)&req, (int)sizeof(req), 0, (struct sockaddr*)&srv, (int)sizeof(srv));

    fp = fopen(saveName, "wb");
    if (!fp) {
        closesocket(sock);
        return s;
    }

    //proje ölçümleri için sayaçlarý baþlatýyor
    totalBytes = 0;
    totalPackets = 0;
    corrupted = 0;
    repaired = 0;
    lossEvents = 0;
    expectedSeq = 0;

    memset(&peer, 0, sizeof(peer));
    havePeer = 0;

    tries = 0;
    skip_current = 0;
    reqTries = 0;

    t0 = now_sec();

    while (1) {
        memset(&pkt, 0, sizeof(pkt));

        fromLen = (int)sizeof(peer);
        //baþta cevap vermediyse 3 kez tekrar deniyo býrakýyo baðlantý esnasýnda cevap gelmezse loss sayýyo
        got = recvfrom(sock, (char*)&pkt, (int)sizeof(pkt), 0, (struct sockaddr*)&peer, &fromLen);

        if (got > 0) havePeer = 1;

        if (got <= 0) {
            if (!havePeer) {
                reqTries++;
                if (reqTries <= 3) {
                    sendto(sock, (char*)&req, (int)sizeof(req), 0, (struct sockaddr*)&srv, (int)sizeof(srv));
                    continue;
                } else {
                    break;
                }
            }

            lossEvents++;
            tries++;

            memset(&resp, 0, sizeof(resp));
            resp.MessageType = MSG_REPAIR;
            resp.SequenceNumber = expectedSeq;
            sendto(sock, (char*)&resp, (int)sizeof(resp), 0, (struct sockaddr*)&peer, fromLen);

            if (tries >= MAX_RETRY) {
                /* burada paketi atliyoruz -> loss olayi bir kez daha */
                lossEvents++;
                tries = 0;
                expectedSeq++;
            }
            continue;
        }

        if (pkt.MessageType == MSG_END) break;
        if (pkt.MessageType != MSG_DATA) continue;
        //Paket boyutu mantýksýzsa kayýp sayýyo
        if (pkt.DataLength < 0 || pkt.DataLength > BUFFER_SIZE) {
            lossEvents++;
            continue;
        }

        if (pkt.SequenceNumber != expectedSeq) {
            //Gelen paket istediðimiz deðilse loss sayar tekrar ister tekrar gelmezse paketi atlar
            lossEvents++;
            tries++;

            memset(&resp, 0, sizeof(resp));
            resp.MessageType = MSG_REPAIR;
            resp.SequenceNumber = expectedSeq;
            sendto(sock, (char*)&resp, (int)sizeof(resp), 0, (struct sockaddr*)&peer, fromLen);

            if (tries >= MAX_RETRY) {
                lossEvents++;
                tries = 0;
                expectedSeq++;
            }
            continue;
        }

        tries = 0;

        //Paket sýrasý doðruysa bozuk mu diye kontrol ediyor
        cs = calculate_checksum(pkt.Data, pkt.DataLength);
        if (cs != pkt.Checksum) {
            corrupted++;//bozuksa corrupted sayýyo


            lossEvents++;

            skip_current = 0;
            tries = 0;

            //ayný mesajý tekrar istiyo
            while (tries < MAX_RETRY) {
                memset(&resp, 0, sizeof(resp));
                resp.MessageType = MSG_REPAIR;
                resp.SequenceNumber = expectedSeq;
                sendto(sock, (char*)&resp, (int)sizeof(resp), 0, (struct sockaddr*)&peer, fromLen);

                memset(&pkt, 0, sizeof(pkt));
                fromLen = (int)sizeof(peer);
                got = recvfrom(sock, (char*)&pkt, (int)sizeof(pkt), 0, (struct sockaddr*)&peer, &fromLen);

                if (got > 0 && pkt.MessageType == MSG_DATA && pkt.SequenceNumber == expectedSeq) {
                    if (pkt.DataLength < 0 || pkt.DataLength > BUFFER_SIZE) {
                        lossEvents++;
                    } else {
                        cs = calculate_checksum(pkt.Data, pkt.DataLength);
                        if (cs == pkt.Checksum) {
                            repaired++;//düzgün gelirse
                            skip_current = 0;
                            break;
                        } else {
                            corrupted++;
                            lossEvents++;
                        }
                    }
                } else {
                    if (got <= 0) lossEvents++;
                }

                tries++;
            }

            if (tries >= MAX_RETRY) skip_current = 1;

            if (skip_current) {
                lossEvents++;
                tries = 0;
                expectedSeq++;
                continue;
            }
        }

        //Paket düzgünse ACK yollayýp dosyaya yazýyor
        memset(&resp, 0, sizeof(resp));
        resp.MessageType = MSG_ACK;
        resp.SequenceNumber = expectedSeq;
        sendto(sock, (char*)&resp, (int)sizeof(resp), 0, (struct sockaddr*)&peer, fromLen);

        fwrite(pkt.Data, 1, (size_t)pkt.DataLength, fp);
        totalBytes += pkt.DataLength;
        totalPackets++;
        expectedSeq++;
    }

    t1 = now_sec();

    fclose(fp);
    closesocket(sock);


    //Proje sonucu için süre ve yüzdeleri hesaplýyor
    s.TotalBytes = totalBytes;
    s.TotalPackets = totalPackets;
    s.CorruptedPackets = corrupted;
    s.RepairedPackets = repaired;
    s.LostPackets = lossEvents;
    s.TransferTimeSec = (t1 - t0);

    if ((s.LostPackets + s.TotalPackets) > 0) {
        s.LossPercent = (100.0 * (double)s.LostPackets) /
                        (double)(s.LostPackets + s.TotalPackets);
    } else {
        s.LossPercent = 0.0;
    }

    if (s.TransferTimeSec > 0.0) {

        s.ThroughputBps = ((double)s.TotalBytes * 8.0) / s.TransferTimeSec;
    }

    return s;
}

//Belirlenen SNR için dosyayý TCP ve UDP ile indip RUNS sayýsý kadar tekrar ederek ortalamasýný alýr
static void measure_for_snr(const char *ip, const char *file, double snr,
                            Stats *tcpAvg, Stats *udpAvg,
                            long *outFileSize, int *outTotalPackets,
                            char *tcpOutName, int tcpOutSize,
                            char *udpOutName, int udpOutSize)
{
    Stats tcpSum, udpSum, t, u;
    int i;
    long fileSize = 0;
    int totalPackets = 0;

    memset(&tcpSum, 0, sizeof(tcpSum));
    memset(&udpSum, 0, sizeof(udpSum));

    make_out_name(tcpOutName, tcpOutSize, "received_tcp_", file);
    make_out_name(udpOutName, udpOutSize, "received_udp_", file);
    append_snr_tag(tcpOutName, tcpOutSize, snr);
    append_snr_tag(udpOutName, udpOutSize, snr);

    for (i = 0; i < RUNS; i++) {
        t = tcp_receive_once(ip, file, snr, tcpOutName);
        u = udp_receive_once(ip, file, snr, udpOutName);

        if (fileSize <= 0) {
            long cand = 0;
            if (t.TotalBytes > 0) cand = t.TotalBytes;
            if (u.TotalBytes > cand) cand = u.TotalBytes;

            if (cand > 0) {
                fileSize = cand;
                totalPackets = (int)((fileSize + BUFFER_SIZE - 1) / BUFFER_SIZE);
            }
        }

        //yapýlan denemelerin sonuçlarýný bir araya topluyo
        tcpSum.TotalPackets += t.TotalPackets;
        udpSum.TotalPackets += u.TotalPackets;
        tcpSum.LostPackets += t.LostPackets;
        udpSum.LostPackets += u.LostPackets;
        tcpSum.CorruptedPackets += t.CorruptedPackets;
        udpSum.CorruptedPackets += u.CorruptedPackets;
        tcpSum.RepairedPackets += t.RepairedPackets;
        udpSum.RepairedPackets += u.RepairedPackets;
        tcpSum.TransferTimeSec += t.TransferTimeSec;
        udpSum.TransferTimeSec += u.TransferTimeSec;
        tcpSum.ThroughputBps += t.ThroughputBps;
        udpSum.ThroughputBps += u.ThroughputBps;
        tcpSum.TotalBytes += t.TotalBytes;
        udpSum.TotalBytes += u.TotalBytes;
    }

    memset(tcpAvg, 0, sizeof(*tcpAvg));
    memset(udpAvg, 0, sizeof(*udpAvg));

    tcpAvg->PacketSize = BUFFER_SIZE;
    udpAvg->PacketSize = BUFFER_SIZE;

    //Ortalamalarýn alýnmasý
    tcpAvg->TotalPackets = (RUNS > 0) ? (tcpSum.TotalPackets / RUNS) : 0;
    udpAvg->TotalPackets = (RUNS > 0) ? (udpSum.TotalPackets / RUNS) : 0;
    tcpAvg->LostPackets = (RUNS > 0) ? (tcpSum.LostPackets / RUNS) : 0;
    udpAvg->LostPackets = (RUNS > 0) ? (udpSum.LostPackets / RUNS) : 0;
    tcpAvg->CorruptedPackets = (RUNS > 0) ? (tcpSum.CorruptedPackets / RUNS) : 0;
    udpAvg->CorruptedPackets = (RUNS > 0) ? (udpSum.CorruptedPackets / RUNS) : 0;

    tcpAvg->TransferTimeSec = (RUNS > 0) ? (tcpSum.TransferTimeSec / (double)RUNS) : 0.0;
    udpAvg->TransferTimeSec = (RUNS > 0) ? (udpSum.TransferTimeSec / (double)RUNS) : 0.0;

    tcpAvg->ThroughputBps = (RUNS > 0) ? (tcpSum.ThroughputBps / (double)RUNS) : 0.0;
    udpAvg->ThroughputBps = (RUNS > 0) ? (udpSum.ThroughputBps / (double)RUNS) : 0.0;

    tcpAvg->TotalBytes = (RUNS > 0) ? (tcpSum.TotalBytes / RUNS) : 0;
    udpAvg->TotalBytes = (RUNS > 0) ? (udpSum.TotalBytes / RUNS) : 0;

    //udp için kayýp yüzdesini tekrar hesaplýyor
    if ((udpAvg->LostPackets + udpAvg->TotalPackets) > 0) {
        udpAvg->LossPercent = (100.0 * (double)udpAvg->LostPackets) /
                              (double)(udpAvg->LostPackets + udpAvg->TotalPackets);
    } else {
        udpAvg->LossPercent = 0.0;
    }

    //dýþarýya dosya sayýsýný ve toplam paket sayýsýný veriyor
    if (outFileSize) *outFileSize = fileSize;
    if (outTotalPackets) *outTotalPackets = totalPackets;
}

void run_client(void)
{
    char ip[64];
    char file[128];

    double snrStart, snrEnd, snrStep, snr;

    Stats tcpA, udpA;
    long fileSize;
    int totalPackets;

    char tcpOut[256];
    char udpOut[256];

    double tcpGoodputMbps, udpGoodputMbps;
    double tcpCorruptPct, udpCorruptPct;

    double berTh, shannonMbps;
    double successTcp, successUdp;

    int packetizationPrinted = 0;
    int firstMeasured = 0; /* ilk SNR olcumunu bir kere yapip kullanacagiz */

    printf("\nServer IP: ");
    scanf("%63s", ip);

    printf("File: ");
    scanf("%127s", file);

    printf("SNR Start (dB): ");
    scanf("%lf", &snrStart);

    printf("SNR End (dB): ");
    scanf("%lf", &snrEnd);

    printf("SNR Step (dB): ");
    scanf("%lf", &snrStep);

    if (snrStep == 0.0) snrStep = 1.0;

    printf("\n[INFO] Each SNR: RUNS=%d (TCP+UDP). MAX_RETRY=%d.\n\n", RUNS, MAX_RETRY);

    printf("===== SNR ANALYSIS SUMMARY (MULTI-SNR) =====\n\n");
    printf("File        : %s\n", file);
    printf("Packet Size : %d bytes\n", BUFFER_SIZE);
    printf("Bandwidth   : %.0f Hz\n\n", CHANNEL_BANDWIDTH);

    if ((snrEnd - snrStart) * snrStep < 0.0) snrStep = -snrStep;

    //ilk snr yi verilerini kullanmak için bir kez ölçüyor
    snr = snrStart;

    measure_for_snr(ip, file, snr, &tcpA, &udpA, &fileSize, &totalPackets,
                    tcpOut, (int)sizeof(tcpOut),
                    udpOut, (int)sizeof(udpOut));
    firstMeasured = 1;

    if (!packetizationPrinted && fileSize > 0 && totalPackets > 0) {
        int lastPayload = (int)(fileSize % BUFFER_SIZE);
        if (lastPayload == 0) lastPayload = BUFFER_SIZE;

        printf("[INFO] Packetization (1 time):\n");
        printf("    FileSize       : %ld bytes\n", fileSize);
        printf("    PacketSize     : %d bytes\n", BUFFER_SIZE);
        printf("    PacketCount    : %d\n", totalPackets);
        printf("    sizeof(Packet) : %u bytes\n", (unsigned)sizeof(Packet));
        printf("    LastPayloadMax : %d bytes\n\n", lastPayload);

        packetizationPrinted = 1;
    }

    printf("SNR(dB) | BER(theory) | Proto | Avg Time(s) | Loss(%%) | Corrupt(%%) | Goodput(Mbps) | Shannon(Mbps) | Success(%%)\n");
    printf("-----------------------------------------------------------------------------------------------------------------\n");


    {
        //TCP ve UDP ile dosya ne hýzla indi
        tcpGoodputMbps = (tcpA.ThroughputBps / 1e6);
        udpGoodputMbps = (udpA.ThroughputBps / 1e6);

        //Bozulma yüzdesi
        tcpCorruptPct = (tcpA.TotalPackets > 0) ? (100.0 * (double)tcpA.CorruptedPackets / (double)tcpA.TotalPackets) : 0.0;
        udpCorruptPct = (udpA.TotalPackets > 0) ? (100.0 * (double)udpA.CorruptedPackets / (double)udpA.TotalPackets) : 0.0;

        //Teorik BER ve Shannon kapasitesi
        berTh = ber_bpsk(snr);
        shannonMbps = shannon_capacity(CHANNEL_BANDWIDTH, snr) / 1e6;

        //Baþarý yüzdesi
        successTcp = (fileSize > 0 && tcpA.TotalBytes >= fileSize) ? 100.0 :
                     ((fileSize > 0) ? (100.0 * (double)tcpA.TotalBytes / (double)fileSize) : 0.0);

        successUdp = (fileSize > 0 && udpA.TotalBytes >= fileSize) ? 100.0 :
                     ((fileSize > 0) ? (100.0 * (double)udpA.TotalBytes / (double)fileSize) : 0.0);

        printf("%-6.0f | %10.3e | %-5s | %10.2f | %7.1f | %10.2f | %12.2f | %11.2f | %9.1f\n",
               snr, berTh, "TCP", tcpA.TransferTimeSec, 0.0, tcpCorruptPct, tcpGoodputMbps, shannonMbps, successTcp);

        printf("%-6.0f | %10.3e | %-5s | %10.2f | %7.1f | %10.2f | %12.2f | %11.2f | %9.1f\n",
               snr, berTh, "UDP", udpA.TransferTimeSec, udpA.LossPercent, udpCorruptPct, udpGoodputMbps, shannonMbps, successUdp);

        append_results_csv(snr, berTh, "TCP", tcpA.TransferTimeSec, 0.0, tcpCorruptPct, tcpGoodputMbps, shannonMbps, successTcp);
        append_results_csv(snr, berTh, "UDP", udpA.TransferTimeSec, udpA.LossPercent, udpCorruptPct, udpGoodputMbps, shannonMbps, successUdp);
    }


    snr += snrStep;

    while (1) {
        if (snrStep > 0.0) { if (snr > snrEnd + 1e-9) break; }
        else { if (snr < snrEnd - 1e-9) break; }

        measure_for_snr(ip, file, snr, &tcpA, &udpA, &fileSize, &totalPackets,
                        tcpOut, (int)sizeof(tcpOut),
                        udpOut, (int)sizeof(udpOut));

        tcpGoodputMbps = (tcpA.ThroughputBps / 1e6);
        udpGoodputMbps = (udpA.ThroughputBps / 1e6);

        tcpCorruptPct = (tcpA.TotalPackets > 0) ? (100.0 * (double)tcpA.CorruptedPackets / (double)tcpA.TotalPackets) : 0.0;
        udpCorruptPct = (udpA.TotalPackets > 0) ? (100.0 * (double)udpA.CorruptedPackets / (double)udpA.TotalPackets) : 0.0;

        berTh = ber_bpsk(snr);
        shannonMbps = shannon_capacity(CHANNEL_BANDWIDTH, snr) / 1e6;

        successTcp = (fileSize > 0 && tcpA.TotalBytes >= fileSize) ? 100.0 :
                     ((fileSize > 0) ? (100.0 * (double)tcpA.TotalBytes / (double)fileSize) : 0.0);

        successUdp = (fileSize > 0 && udpA.TotalBytes >= fileSize) ? 100.0 :
                     ((fileSize > 0) ? (100.0 * (double)udpA.TotalBytes / (double)fileSize) : 0.0);

        printf("%-6.0f | %10.3e | %-5s | %10.2f | %7.1f | %10.2f | %12.2f | %11.2f | %9.1f\n",
               snr, berTh, "TCP", tcpA.TransferTimeSec, 0.0, tcpCorruptPct, tcpGoodputMbps, shannonMbps, successTcp);

        printf("%-6.0f | %10.3e | %-5s | %10.2f | %7.1f | %10.2f | %12.2f | %11.2f | %9.1f\n",
               snr, berTh, "UDP", udpA.TransferTimeSec, udpA.LossPercent, udpCorruptPct, udpGoodputMbps, shannonMbps, successUdp);

        append_results_csv(snr, berTh, "TCP", tcpA.TransferTimeSec, 0.0, tcpCorruptPct, tcpGoodputMbps, shannonMbps, successTcp);
        append_results_csv(snr, berTh, "UDP", udpA.TransferTimeSec, udpA.LossPercent, udpCorruptPct, udpGoodputMbps, shannonMbps, successUdp);

        snr += snrStep;
    }

    printf("\n[INFO] Last saved files (for last SNR):\n");
    printf("TCP -> %s\n", tcpOut);
    printf("UDP -> %s\n", udpOut);

    printf("\n[INFO] All results appended to -> results.csv\n");

    printf("\nPress ENTER to exit...");
    getchar();
    getchar();
}
