#include "AES.h"
#include <stdio.h>

//declar rcon array
unsigned char rcon[10][4] = {
    0x01, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00,
    0x08, 0x00, 0x00, 0x00,
    0x10, 0x00, 0x00, 0x00,
    0x20, 0x00, 0x00, 0x00,
    0x40, 0x00, 0x00, 0x00,
    0x80, 0x00, 0x00, 0x00,
    0x1b, 0x00, 0x00, 0x00,
    0x36, 0x00, 0x00, 0x00
};

//declare sbox array
unsigned char sbox[16][16] = {
    // 0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, //0
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, //1
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, //2
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, //3
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, //4
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, //5
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, //6
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, //7
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, //8
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, //9
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, //A
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, //B
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, //C
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, //D
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, //E
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16  //F
};

//declare inv sbox array
unsigned char invsbox[16][16] = {
    // 0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb, //0
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, //1
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e, //2
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, //3
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, //4
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, //5
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06, //6
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, //7
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73, //8
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, //9
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, //A
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, //B
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, //C
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, //D
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, //E
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d  //F
};

//state xor with the key 
void AddRoundKey(unsigned char *state, unsigned char *key)
{
    int i, j;
    for (i = 0; i < 16; i++)
    {
        *(state + i) = *(state + i) ^ *(key + i); //xor state element with key 
    }
}

//state multiple(GF2) with mix matrix
void MixColumn(unsigned char *state)
{
    int i, j;
    for (i = 0; i < 4; i++)
    {
        unsigned char d1 = *(state + 4 * i), d2 = *(state + 4 * i + 1), d3 = *(state + 4 * i + 2), d4 = *(state + 4 * i + 3);
        *(state + 4 * i) = Mix_mul2(d1) ^ Mix_mul2(d2) ^ d2 ^ (1 * d3) ^ (1 * d4);      // 2*d1 ^ 3*d2 ^ 1*d3 ^ 1*d4 
        *(state + 4 * i + 1) = (1 * d1) ^ Mix_mul2(d2) ^ Mix_mul2(d3) ^ d3 ^ (1 * d4);  // 1*d1 ^ 2*d2 ^ 3*d3 ^ 1*d4
        *(state + 4 * i + 2) = (1 * d1) ^ (1 * d2) ^ Mix_mul2(d3) ^ Mix_mul2(d4) ^ d4;  // 1*d1 ^ 1*d2 ^ 2*d3 ^ 3*d4
        *(state + 4 * i + 3) = Mix_mul2(d1) ^ d1 ^ (1 * d2) ^ (1 * d3) ^ Mix_mul2(d4);  // 3*d1 ^ 1*d2 ^ 1*d3 ^ 2*d4
    }
}

//state replace with s-box
void SubBytes(unsigned char *state)
{
    char test = 0x0F;
    int temp1, temp2;
    int i, j;
    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < 4; j++)
        {
            temp1 = *(state + (i + 4 * j)) >> 4; //lefthead 4 bits
            temp2 = *(state + (i + 4 * j)) & test; //righthead 4 bits
            *(state + (i + 4 * j)) = sbox[temp1][temp2]; //replcae 1 btye
        }
    }
}

//state left shift for no.column(s) time 
void ShiftRows(unsigned char *state)
{
    int i, j;
    int temp1, temp2, temp3, temp4;

    for (i = 0; i < 4; i++)
    {
        temp1 = *(state + i);
        temp2 = *(state + i + 4);
        temp3 = *(state + i + 8);
        temp4 = *(state + i + 12);
        //i = 0 shift 0 times
        if (i == 1)
        {
            *(state + i) = temp2;
            *(state + i + 4) = temp3;
            *(state + i + 8) = temp4;
            *(state + i + 12) = temp1;
        }
        else if (i == 2)
        {
            *(state + i) = temp3;
            *(state + i + 4) = temp4;
            *(state + i + 8) = temp1;
            *(state + i + 12) = temp2;
        }
        else if (i == 3)
        {
            *(state + i) = temp4;
            *(state + i + 4) = temp1;
            *(state + i + 8) = temp2;
            *(state + i + 12) = temp3;
        }
    }
}

//replace with inv s-box
void InvSubBytes(unsigned char *state)
{
    char test = 0x0F;
    int temp1, temp2;
    int i, j;
    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < 4; j++)
        {
            temp1 = *(state + (i + 4 * j)) >> 4; //lefthead 4 bits
            temp2 = *(state + (i + 4 * j)) & test; //righthead 4 bits
            *(state + (i + 4 * j)) = invsbox[temp1][temp2];//replace 1 byte
        }
    }
}

//GF2 multiple implement
unsigned char Mix_mul2(unsigned char target)
{
    if (target >= 128)
    {
        return target << 1 ^ 0x1b;//target>128 have extra xor 0x1b 
    }
    else
    {
        return target << 1; //multiple 2 (shift 2)
    }
}

//state multiple with inv matrix (GF2 multiple)
void InvMixColumn(unsigned char *state)
{
    int i, j;
    for (i = 0; i < 4; i++)
    {
        unsigned char d1 = *(state + 4 * i), d2 = *(state + 4 * i + 1), d3 = *(state + 4 * i + 2), d4 = *(state + 4 * i + 3);

        *(state + 4 * i) = (Mix_mul2(Mix_mul2((Mix_mul2(d1) ^ d1)) ^ d1)) ^
                           (Mix_mul2(Mix_mul2(Mix_mul2(d2)) ^ d2) ^ d2) ^
                           (Mix_mul2(Mix_mul2(Mix_mul2(d3) ^ d3)) ^ d3) ^
                           (Mix_mul2(Mix_mul2(Mix_mul2(d4))) ^ d4);
        //15*d1 ^ 11*d2 ^ 13*d3 ^ 9*d4
        *(state + 4 * i + 1) = (Mix_mul2(Mix_mul2(Mix_mul2(d1))) ^ d1) ^
                               (Mix_mul2(Mix_mul2((Mix_mul2(d2) ^ d2)) ^ d2)) ^
                               (Mix_mul2(Mix_mul2(Mix_mul2(d3)) ^ d3) ^ d3) ^
                               (Mix_mul2(Mix_mul2(Mix_mul2(d4) ^ d4)) ^ d4);
        //9*d1 ^ 15*d2 ^ 11*d3 ^ 13*d4
        *(state + 4 * i + 2) = (Mix_mul2(Mix_mul2(Mix_mul2(d1) ^ d1)) ^ d1) ^
                               (Mix_mul2(Mix_mul2(Mix_mul2(d2))) ^ d2) ^
                               (Mix_mul2(Mix_mul2((Mix_mul2(d3) ^ d3)) ^ d3)) ^
                               (Mix_mul2(Mix_mul2(Mix_mul2(d4)) ^ d4) ^ d4);
        //13*d1 ^ 9*d2 ^ 15*d3 ^ 11*d4
        *(state + 4 * i + 3) = (Mix_mul2(Mix_mul2(Mix_mul2(d1)) ^ d1) ^ d1) ^
                               (Mix_mul2(Mix_mul2(Mix_mul2(d2) ^ d2)) ^ d2) ^
                               (Mix_mul2(Mix_mul2(Mix_mul2(d3))) ^ d3) ^
                               (Mix_mul2(Mix_mul2((Mix_mul2(d4) ^ d4)) ^ d4));
        //11*d1 ^ 13*d2 ^ 9*d3 ^ 15*d4
    }
}

//state shift right for invert
void InvShiftRows(unsigned char *state)
{
    int i;
    int temp1, temp2, temp3, temp4;

    for (i = 0; i < 4; i++)
    {
        temp1 = *(state + i);
        temp2 = *(state + i + 4);
        temp3 = *(state + i + 8);
        temp4 = *(state + i + 12);
        //i==0 right shift 0 column
        if (i == 1)
        {
            *(state + i) = temp4;
            *(state + i + 4) = temp1;
            *(state + i + 8) = temp2;
            *(state + i + 12) = temp3;
        }
        else if (i == 2)
        {
            *(state + i) = temp3;
            *(state + i + 4) = temp4;
            *(state + i + 8) = temp1;
            *(state + i + 12) = temp2;
        }
        else if (i == 3)
        {
            *(state + i) = temp2;
            *(state + i + 4) = temp3;
            *(state + i + 8) = temp4;
            *(state + i + 12) = temp1;
        }
    }
}

//generate key table
void KeySchedule(unsigned char *key, int N)
{
    int i, j;
    unsigned char *M, *M_1, *M_N;
    char test = 0x0F;
    char temp1, temp2;
    M = key + N * 4;
    M_1 = M - 4;
    M_N = key;
    for (i = 4 * N; i < (N + 7) * 16 - 1; i++)
    {
        *(key + i) = 0;
    }

    for (i = 0; i < 4 * (7 + N); i++)
    {
        if (i < N)
        {
            continue;
        }
        else if (i % N == 4 && N > 6 && i >= N)
        {
            for (j = 0; j < 4; j++)
            {
                temp1 = *(M_1 + j) >> 4;
                temp2 = *(M_1 + j) & test;
                *(M + j) = *(M_N + j) ^ sbox[temp1][temp2];
            }
        }
        else if (i % N == 0 && i >= N)
        {
            for (j = 0; j < 4; j++)
            {
                temp1 = *(M_1 + ((j + 1) % 4)) >> 4;
                temp2 = *(M_1 + ((j + 1) % 4)) & test;
                *(M + j) = *(M_N + j) ^ sbox[temp1][temp2] ^ rcon[i / N - 1][j];
            }
        }
        else
        {
            for (j = 0; j < 4; j++)
            {
                *(M + j) = *(M_1 + j) ^ *(M_N + j);
            }
        }
        M += 4;
        M_N += 4;
        M_1 += 4;
    }

}

//show key with N (for test)
void showkey(unsigned char *key, int N)
{
    int i, j, k;
    for (i = 0; i < N + 7; i++)
    {
        printf("this is %d key round\n", i);
        for (j = 0; j < 4; j++)
        {
            for (k = 0; k < 4; k++)
            {
                printf("%02x ", *(key + i * 16 + (j + 1 * 4 * k)));
            }
            printf("\n");
        }
    }
}

//show IV or state (for test)
void show(unsigned char *state)
{
    int i, j;
    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < 4; j++)
        {
            printf("%02x ", *(state + (i + 4 * j)));
        }
        printf("\n");
    }
}

//AES enctrypt for N+6 round with keytable 
void AES_encrypt(char *state, char *key, int N){
    for(int i=0;i<N+7;i++){
        if(i==0){
            //initial state
            AddRoundKey(state,key); 
        }
        else if(i==N+6){
            //last round
            SubBytes(state);
            ShiftRows(state);
            AddRoundKey(state,key+16*i);
        }
        else{
            //other round
            SubBytes(state);
            ShiftRows(state);
            MixColumn(state);
            AddRoundKey(state,key+16*i);
        }
    }
}

//AES dectrypt for N+6 round with keytable
void AES_decrypt(char *state, char *key, int N){
    for(int i=N+6;i>=0;i--){
        if(i==0){
            //last state
            AddRoundKey(state,key+16*i);
        }
        else if(i==N+6){
            //first round
            AddRoundKey(state,key+16*i);
            InvShiftRows(state);
            InvSubBytes(state);
        }
        else{
            //other round
            AddRoundKey(state,key+16*i);
            InvMixColumn(state);
            InvShiftRows(state);
            InvSubBytes(state);
        }
    }
}



