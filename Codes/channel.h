#ifndef CHANNEL_H
#define CHANNEL_H

#include "common.h"

// SNR(dB) -> linear
double snr_db_to_linear(double snrDb);

// BPSK over AWGN teorik BER
double ber_bpsk(double snrDb);

// Shannon kapasitesi: C = B * log2(1 + SNR)
double shannon_capacity(double bandwidthHz, double snrDb);

// Bit flip gürültüsü uygular
void apply_noise(char *data, int len, double snrDb);

// UDP icin: paketi "drop" edip etmemeye karar ver (0/1)
int should_drop_packet(int payloadLen, double snrDb);

#endif /* CHANNEL_H */


