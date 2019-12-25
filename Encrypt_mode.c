#include "Encrypt_mode.h"
#include "AES.h"
#include "bit_operation.h"
#include <stdlib.h>
#include <stdio.h>

void ECB_en(char *file){
    int i, keylen, N, exit_flag = 0;
    int end_flag = 1, index = 16;
    unsigned char *state, *key_state;
    FILE *origin_data = fopen(file, "r+");
    FILE *output = fopen("en_Output", "w");
    FILE *key;
    printf("\n(1)128\n(2)192\n(3)256\n");
    printf("Key length:");
    scanf("%d", &keylen);

    switch (keylen)
    {
    case 1:
        N = 4;
        break;
    case 2:
        N = 6;
        break;
    case 3:
        N = 8;
        break;
    }

    state = (char *)malloc(sizeof(char) * 16);
    key_state = (char *)malloc(sizeof(char *) * 16 * (7 + N));

    key = fopen("randomKey", "w+");
    for (i = 0; i < 4 * N; i++)
    {
        *(key_state + i) = rand() % 256;
        fwrite(key_state + i, 1, 1, key);
    }
    KeySchedule(key_state, N);

    while (end_flag)
    {
        cleanbuffer(state);
        for (i = 0; i < 16; i++)
        {
            fread(state + i, 1, 1, origin_data);
            if (feof(origin_data))
            {
                end_flag = 0;
                index = i;
                fwrite(&index, 1, 1, key);
                if (i == 0)
                {
                    exit_flag = 1;
                }
                break;
            }
        }
        if (exit_flag == 1)
        {
            break;
        }
        AES_encrypt(state, key_state, N);
        fwrite(state, 16, 1, output);
    }
}

void CBC_en(char *file){
    int end_flag = 1, index = 16, exit_flag = 0;
    int mode, i, N, keylen;
    unsigned char *state, *IV, *key_state;
    FILE *origin_data = fopen(file, "r+");
    FILE *output = fopen("en_Output", "w");
    FILE *key;
    FILE *Initial_Vector;
    printf("\n(1)128\n(2)192\n(3)256\n");
    printf("Key length:");
    scanf("%d", &keylen);
    Initial_Vector = fopen("IV", "w+");
    IV = (char *)malloc(sizeof(char) * 16);
    for (i = 0; i < 16; i++)
    {
        *(IV + i) = rand() % 256;
    }
    fwrite(IV, 16, 1, Initial_Vector);
    switch (keylen)
    {
    case 1:
        N = 4;
        break;
    case 2:
        N = 6;
        break;
    case 3:
        N = 8;
        break;
    }

    state = (char *)malloc(sizeof(char) * 16);
    key_state = (char *)malloc(sizeof(char *) * 16 * (7 + N));

    key = fopen("randomKey", "w+");
    for (i = 0; i < 4 * N; i++)
    {
        *(key_state + i) = rand() % 256;
        fwrite(key_state + i, 1, 1, key);
    }
    KeySchedule(key_state, N);

    while (end_flag)
    {
        cleanbuffer(state);
        for (i = 0; i < 16; i++)
        {
            fread(state + i, 1, 1, origin_data);
            if (feof(origin_data))
            {
                end_flag = 0;
                index = i;
                fwrite(&index, 1, 1, key);
                if (i == 0)
                {
                    exit_flag = 1;
                }
                break;
            }
        }
        if (exit_flag)
        {
            break;
        }
        for (i = 0; i < 16; i++)
        {
            *(state + i) = *(state + i) ^ *(IV + i);
        }
        AES_encrypt(state, key_state, N);
        fwrite(state, 16, 1, output);
        for (i = 0; i < 16; i++)
        {
            *(IV + i) = *(state + i);
        }
    }
}

void CTR_en(char *file){
    int end_flag = 1, index = 16, exit_flag = 0;
    int mode, i, N, keylen, temp;
    unsigned char *state, *IV, *temp_IV, *key_state;
    FILE *origin_data = fopen(file, "r+");
    FILE *output = fopen("en_Output", "w");
    FILE *key;
    FILE *Initial_Vector;
    printf("\n(1)128\n(2)192\n(3)256\n");
    printf("Key length:");
    scanf("%d", &keylen);
    switch (keylen)
    {
    case 1:
        N = 4;
        break;
    case 2:
        N = 6;
        break;
    case 3:
        N = 8;
        break;
    }
    Initial_Vector = fopen("IV", "w+");
    IV = (char *)malloc(sizeof(char) * 16);
    temp_IV = (char *)malloc(sizeof(char) * 16);
    for (i = 0; i < 16; i++)
    {
        *(IV + i) = rand() % 256;
    }
    fwrite(IV, 16, 1, Initial_Vector);

    state = (char *)malloc(sizeof(char) * 16);
    key_state = (char *)malloc(sizeof(char *) * 16 * (7 + N));

    key = fopen("randomKey", "w+");
    for (i = 0; i < 4 * N; i++)
    {
        *(key_state + i) = rand() % 256;
        fwrite(key_state + i, 1, 1, key);
    }
    KeySchedule(key_state, N);

    while (end_flag)
    {
        cleanbuffer(state);
        for (i = 0; i < 16; i++)
        {
            fread(state + i, 1, 1, origin_data);
            if (feof(origin_data))
            {
                end_flag = 0;
                index = i;
                fwrite(&index, 1, 1, key);
                if (i == 0)
                {
                    exit_flag = 1;
                }
                break;
            }
        }

        if (exit_flag)
        {
            break;
        }

        copy(temp_IV,IV);
        AES_encrypt(IV, key_state, N);
        for (i = 0; i < 16; i++)
        {
            *(state + i) = *(state + i) ^ *(IV + i);
        }
        fwrite(state, 16, 1, output);
        copy(IV,temp_IV);
        for (i = 15; i >= 0; i--)
        {
            if (*(IV + i) == 0xff)
            {
                *(IV + i) = 0x00;
            }
            else
            {
                *(IV + i) += 1;
                break;
            }
        }
    }
}

void CFB_8_en(char *file){
    int end_flag = 1, exit_flag = 0;
    int i,j, N, keylen, index;
    unsigned char *IV, *temp_IV, *state, *key_state;
    FILE *origin_data = fopen(file, "r+");
    FILE *output = fopen("en_Output", "w");
    FILE *key;
    FILE *Initial_Vector;
    printf("\n(1)128\n(2)192\n(3)256\n");
    printf("Key length:");
    scanf("%d", &keylen);
    switch (keylen)
    {
    case 1:
        N = 4;
        break;
    case 2:
        N = 6;
        break;
    case 3:
        N = 8;
        break;
    }
    Initial_Vector = fopen("IV", "w+");
    IV = (char *)malloc(sizeof(char) * 16);
    temp_IV = (char *)malloc(sizeof(char) * 16);
    for (i = 0; i < 16; i++)
    {
        *(IV + i) = rand() % 256;
    }
    fwrite(IV, 16, 1, Initial_Vector);

    state = (char *)malloc(sizeof(char) * 16);
    key_state = (char *)malloc(sizeof(char *) * 16 * (7 + N));

    key = fopen("randomKey", "w+");
    for (i = 0; i < 4 * N; i++)
    {
        *(key_state + i) = rand() % 256;
        fwrite(key_state + i, 1, 1, key);
    }
    KeySchedule(key_state, N);

    while (end_flag)
    {
        cleanbuffer(state);
        for (i = 0; i < 16; i++)
        {
            fread(state + i, 1, 1, origin_data);
            if (feof(origin_data))
            {
                end_flag = 0;
                index = i;
                fwrite(&index, 1, 1, key);
                if (i == 0)
                {
                    exit_flag = 1;
                }
                break;
            }
        }

        if (exit_flag)
        {
            break;
        }
        for(i=0;i<16;i++){
            copy(temp_IV,IV);
            AES_encrypt(IV,key_state,N);
            *state = *state ^ *IV;
            fwrite(state,1,1,output);
            copy(IV,temp_IV);
            shift_8(IV);
            *(IV+15) = *state;
            shift_8(state);
        }
    }
    fclose(output);
    fclose(origin_data);
    fclose(key);
    fclose(Initial_Vector);
}

void CFB_1_en(char *file) {
    int end_flag = 1, exit_flag = 0;
    int i,j, N, keylen, index;
    unsigned char *IV, *temp_IV, *state, *key_state,out=0x00;
    FILE *origin_data = fopen(file, "r+");
    FILE *output = fopen("en_Output", "w");
    FILE *key;
    FILE *Initial_Vector;
    printf("\n(1)128\n(2)192\n(3)256\n");
    printf("Key length:");
    scanf("%d", &keylen);
    switch (keylen)
    {
    case 1:
        N = 4;
        break;
    case 2:
        N = 6;
        break;
    case 3:
        N = 8;
        break;
    }
    Initial_Vector = fopen("IV", "w+");
    IV = (char *)malloc(sizeof(char) * 16);
    temp_IV = (char *)malloc(sizeof(char) * 16);
    for (i = 0; i < 16; i++)
    {
        *(IV + i) = rand() % 256;
    }
    fwrite(IV, 16, 1, Initial_Vector);
    copy(temp_IV,IV);
    state = (char *)malloc(sizeof(char) * 16);
    key_state = (char *)malloc(sizeof(char *) * 16 * (7 + N));

    key = fopen("randomKey", "w+");
    for (i = 0; i < 4 * N; i++)
    {
        *(key_state + i) = rand() % 256;
        fwrite(key_state + i, 1, 1, key);
    }
    KeySchedule(key_state, N);

    while (end_flag){
        cleanbuffer(state);
        for (i = 0; i < 16; i++)
        {
            fread(state + i, 1, 1, origin_data);
            if (feof(origin_data))
            {
                end_flag = 0;
                index = i;
                fwrite(&index, 1, 1, key);
                if (i == 0)
                {
                    exit_flag = 1;
                }
                break;
            }
        }

        if (exit_flag)
        {
            break;
        }

        for(i=1;i<=128;i++){
            AES_encrypt(IV,key_state,N);
            *IV = *state ^ *IV;
            *IV = *IV & 0x80;
            shift_1(temp_IV);
            if(*IV == 0x00){
                *(temp_IV+15) = *(temp_IV+15) & 0xfe;
            }
            else{
                *(temp_IV+15) = *(temp_IV+15) | 0x01;         
            }
            
            if(i%8!=0){
                *IV = *IV >> 7;
                out = out | *IV;
                out = out << 1;
            }
            else{
                *IV = *IV >> 7;
                out = out | *IV;    
            }
            if(i%8==0){
                fwrite(&out,1,1,output);
                out = 0x00;
            }
            copy(IV,temp_IV);
            shift_1(state);
        }        
    }
    fclose(output);
    fclose(origin_data);
    fclose(key);
    fclose(Initial_Vector);
}

void OFB_8_en(char *file) {
    int end_flag = 1, exit_flag = 0;
    int i,j, N, keylen, index;
    unsigned char *IV, *temp_IV, *state, *key_state;
    FILE *origin_data = fopen(file, "r+");
    FILE *output = fopen("en_Output", "w");
    FILE *key;
    FILE *Initial_Vector;
    printf("\n(1)128\n(2)192\n(3)256\n");
    printf("Key length:");
    scanf("%d", &keylen);
    switch (keylen)
    {
    case 1:
        N = 4;
        break;
    case 2:
        N = 6;
        break;
    case 3:
        N = 8;
        break;
    }
    Initial_Vector = fopen("IV", "w+");
    IV = (char *)malloc(sizeof(char) * 16);
    temp_IV = (char *)malloc(sizeof(char) * 16);
    for (i = 0; i < 16; i++)
    {
        *(IV + i) = rand() % 256;
    }
    fwrite(IV, 16, 1, Initial_Vector);
    copy(temp_IV,IV);

    state = (char *)malloc(sizeof(char) * 16);
    key_state = (char *)malloc(sizeof(char *) * 16 * (7 + N));

    key = fopen("randomKey", "w+");
    for (i = 0; i < 4 * N; i++)
    {
        *(key_state + i) = rand() % 256;
        fwrite(key_state + i, 1, 1, key);
    }

    KeySchedule(key_state, N);

    while (end_flag){
        cleanbuffer(state);
        for (i = 0; i < 16; i++)
        {
            fread(state + i, 1, 1, origin_data);
            if (feof(origin_data))
            {
                end_flag = 0;
                index = i;
                fwrite(&index, 1, 1, key);
                if (i == 0)
                {
                    exit_flag = 1;
                }
                break;
            }
        }

        if (exit_flag)
        {
            break;
        }

        for(i=0;i<16;i++){
            AES_encrypt(IV,key_state,N);
            shift_8(temp_IV);
            *(temp_IV+15) = *IV;
            *state = *state ^ *IV;
            fwrite(state,1,1,output);
            shift_8(state);
            copy(IV,temp_IV);
        }

    }
    fclose(output);
    fclose(origin_data);
    fclose(key);
    fclose(Initial_Vector);
}

void OFB_1_en(char *file) {
    int end_flag = 1, exit_flag = 0;
    int i,j, N, keylen, index;
    unsigned char *IV, *temp_IV, *state, *key_state,out=0x00,test;
    FILE *origin_data = fopen(file, "r+");
    FILE *output = fopen("en_Output", "w");
    FILE *key;
    FILE *Initial_Vector;
    printf("\n(1)128\n(2)192\n(3)256\n");
    printf("Key length:");
    scanf("%d", &keylen);
    switch (keylen)
    {
    case 1:
        N = 4;
        break;
    case 2:
        N = 6;
        break;
    case 3:
        N = 8;
        break;
    }
    Initial_Vector = fopen("IV", "w+");
    IV = (char *)malloc(sizeof(char) * 16);
    temp_IV = (char *)malloc(sizeof(char) * 16);
    for (i = 0; i < 16; i++)
    {
        *(IV + i) = rand() % 256;
    }
    fwrite(IV, 16, 1, Initial_Vector);
    copy(temp_IV,IV);
    state = (char *)malloc(sizeof(char) * 16);
    key_state = (char *)malloc(sizeof(char *) * 16 * (7 + N));

    key = fopen("randomKey", "w+");
    for (i = 0; i < 4 * N; i++)
    {
        *(key_state + i) = rand() % 256;
        fwrite(key_state + i, 1, 1, key);
    }
    KeySchedule(key_state, N);

    while (end_flag){
        cleanbuffer(state);
        for (i = 0; i < 16; i++)
        {
            fread(state + i, 1, 1, origin_data);
            if (feof(origin_data))
            {
                end_flag = 0;
                index = i;
                fwrite(&index, 1, 1, key);
                if (i == 0)
                {
                    exit_flag = 1;
                }
                break;
            }
        }

        if (exit_flag)
        {
            break;
        }

        for(i=1;i<=128;i++){
            AES_encrypt(IV,key_state,N);
            test = *IV & 0x80;
            shift_1(temp_IV);
            if(test == 0x00){
                *(temp_IV+15) = *(temp_IV+15) & 0xfe;
            }
            else{
                *(temp_IV+15) = *(temp_IV+15) | 0x01;         
            }
            *IV = *state ^ *IV;
            
            if(i%8!=0){
                *IV = *IV >> 7;
                out = out | *IV;
                out = out << 1;
            }
            else{
                *IV = *IV >> 7;
                out = out | *IV;    
            }
            if(i%8==0){
                fwrite(&out,1,1,output);
                out = 0x00;
            }
            copy(IV,temp_IV);
            shift_1(state);
        }        
    }
    fclose(output);
    fclose(origin_data);
    fclose(key);
    fclose(Initial_Vector);
}

