//
//  mySHA256.cpp
//
//  Created by Vikram Singh on 12/02/2017.
//  Copyright © 2017 Vikram Singh.
//
//  This is my simple implementation to learn the SHA 256 algorithm.
//  Do not use it for any real work. Assume that it does not work correctly.
//
//  This implements the SHA256 spec from http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
//

#include <iostream>
using namespace std;

uint32_t K[64] =
   {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

uint32_t H[8] =
   {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

inline
uint32_t Ch(uint32_t x, uint32_t y, uint32_t z) {
    return ((x & y) ^ (~x & z));
}

inline
uint32_t Maj(uint32_t x, uint32_t y, uint32_t z) {
    return ((x & y) ^ (x & z) ^ (y & z));
}

inline
uint32_t ROTR(uint32_t x, long n) {
    return ((x >> n) | (x << (32 - n)));
}

inline
uint32_t SHR(uint32_t x, long n) {
    return (x >> n);
}

inline
uint32_t Sig0(uint32_t x) {
    return ROTR(x,2) ^ ROTR(x,13) ^ ROTR(x, 22);
}

inline
uint32_t Sig1(uint32_t x) {
    return ROTR(x,6) ^ ROTR(x,11) ^ ROTR(x, 25);
}

inline
uint32_t sig0(uint32_t x) {
    return ROTR(x,7) ^ ROTR(x,18) ^ SHR(x, 3);
}

inline
uint32_t sig1(uint32_t x) {
    return ROTR(x,17) ^ ROTR(x,19) ^ SHR(x, 10);
}


void printBlk(unsigned char* message) {
    for (long i = 0; i < 64; i++) {
        printf("%02x ", message[i]);
    }
    printf("\n");
}

void hashM(unsigned char* M) {
    // printBlk(M);
    uint32_t W[64];
    for (long t = 0; t < 64; t += 4) {
        W[t/4] = (uint32_t(M[t]) << 24) + (uint32_t(M[t+1]) << 16) + (uint32_t(M[t+2]) << 8) + (uint32_t(M[t+3]));
    }
    for (long t = 16; t < 64; t++) {
        W[t] = sig1(W[t-2]) + W[t-7] + sig0(W[t-15]) + W[t-16];
    }
    
    uint32_t a = H[0];
    uint32_t b = H[1];
    uint32_t c = H[2];
    uint32_t d = H[3];
    uint32_t e = H[4];
    uint32_t f = H[5];
    uint32_t g = H[6];
    uint32_t h = H[7];
    uint32_t T1, T2;
    
    for (long t = 0; t < 64; t++) {
        T1 = h + Sig1(e) + Ch(e,f,g) + K[t] + W[t];
        T2 = Sig0(a) + Maj(a,b,c);
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;
    }
    
    H[0] += a;
    H[1] += b;
    H[2] += c;
    H[3] += d;
    H[4] += e;
    H[5] += f;
    H[6] += g;
    H[7] += h;
    
}


int main(int argc, const char * argv[]) {
    int inChar;
    uint64_t totalLen = 0;
    int b = 0;
    unsigned char message[64];

    while ((inChar = cin.get()) != EOF) {
        //printf("0x%08x\n", inChar);
        message[b++] = inChar;
        totalLen += 8;
        if (b == 512/8) {
            b = 0;
            hashM(message);
        }
    }
    
    message[b++] = 0x80;
    while(b != 448/8) {
        message[b++] = 0x00;
        if (b == 512/8) {
            hashM(message);
            b = 0;
        }
    }
    for (long s = 7; s >= 0; s--) {
        message[b++] = ((totalLen >> (8*s)) & 0xff);
    }
    hashM(message);
    
    for (long i = 0; i < 8; i++) {
        printf("%08x", H[i]);
    }
    printf("\n");
    return 0;
}
