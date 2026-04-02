#include "channel.h"
#include <math.h>
#include <stdlib.h>
#include <time.h>
#include <stdint.h>


#ifndef LOG2_FALLBACK
#define LOG2_FALLBACK(x) (log(x) / log(2.0))
#endif


#define BER_MAX 0.001

double snr_db_to_linear(double snrDb)
{
    return pow(10.0, snrDb / 10.0);
}


static double qfunc_approx(double x)
{
    const double p  = 0.2316419;
    const double a1 = 0.319381530;
    const double a2 = -0.356563782;
    const double a3 = 1.781477937;
    const double a4 = -1.821255978;
    const double a5 = 1.330274429;

    double t, poly, phi;

    if (x < 0.0) x = -x;

    t = 1.0 / (1.0 + p * x);
    poly = ((((a5 * t + a4) * t + a3) * t + a2) * t + a1) * t;
    phi = 0.3989422804014327 * exp(-0.5 * x * x);

    return phi * poly;
}

double ber_bpsk(double snrDb)
{
    double snrLinear, x, ber;

    snrLinear = snr_db_to_linear(snrDb);
    x = sqrt(2.0 * snrLinear);

    ber = qfunc_approx(x);

    if (ber > BER_MAX) ber = BER_MAX;
    if (ber < 0.0) ber = 0.0;

    return ber;
}

double shannon_capacity(double bandwidthHz, double snrDb)
{
    double snrLinear;
    snrLinear = snr_db_to_linear(snrDb);
    return bandwidthHz * LOG2_FALLBACK(1.0 + snrLinear);
}


static unsigned int xorshift32(unsigned int *state)
{
    unsigned int x = *state;
    if (x == 0u) x = 2463534242u;

    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;

    *state = x;
    return x;
}


void apply_noise(char *data, int len, double snrDb)
{
    double ber;
    int i;
    unsigned char b, mask;
    unsigned int rng;

    static unsigned int state = 0;

    if (!data || len <= 0) return;


    if (snrDb >= 40.0) return;

    ber = ber_bpsk(snrDb);
    if (ber < 1e-12) return;

    {
        const double PER_CAP = 0.30;
        double bits = 8.0 * (double)len;
        double berCap;

        if (bits > 0.0) {
            berCap = 1.0 - pow(1.0 - PER_CAP, 1.0 / bits);
            if (ber > berCap) ber = berCap;
        }
    }

    if (state == 0u) {
        state = (unsigned int)time(NULL)
              ^ (unsigned int)(uintptr_t)data
              ^ (unsigned int)len
              ^ 0x9E3779B9u;
    }

    for (i = 0; i < len; i++) {
        b = (unsigned char)data[i];


        rng = xorshift32(&state);

        if ((double)rng / 4294967295.0 < (ber * 8.0)) {
            mask = (unsigned char)(xorshift32(&state) & 0xFFu);
            data[i] = (char)(b ^ mask);
        }
    }
}


int should_drop_packet(int payloadLen, double snrDb)
{
    double ber, bits, per, dropProb, r;

    if (payloadLen <= 0) return 0;
    if (snrDb >= 40.0) return 0;

    ber = ber_bpsk(snrDb);
    if (ber < 1e-12) return 0;

    bits = 8.0 * (double)payloadLen;


    per = 1.0 - pow(1.0 - ber, bits);


    dropProb = per * 0.60;
    if (dropProb > 0.15) dropProb = 0.15;
    if (dropProb < 0.0) dropProb = 0.0;

    r = (double)rand() / (double)RAND_MAX;
    return (r < dropProb) ? 1 : 0;
}
