#include "Decrypt_mode.h"
#include "AES.h"
#include "bit_operation.h"
#include <stdlib.h>
#include <stdio.h>

//Electronic codebook encrypt
void ECB_de(char * file, char * keyfile, int fast) {
    int index = 16;
    int mode, i, N, keylen, size;
    unsigned char * state, * key_state;
    FILE * origin_data = fopen(file, "r+");
    FILE * output = fopen("de_Output", "w");
    FILE * key;

    //get file size
    fseek(origin_data, 0, SEEK_END);
    size = ftell(origin_data);
    fseek(origin_data, 0, SEEK_SET);

    printf("\n(1)128\n(2)192\n(3)256\n");
    printf("Key length:");
    scanf("%d", & keylen);

    switch (keylen) {
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

    key_state = (char * ) malloc(sizeof(char * ) * 16 * (7 + N));
    state = (char * ) malloc(sizeof(char) * 16);

    key = fopen(keyfile, "r");
    fread(key_state, N * 4, 1, key);
    KeySchedule(key_state, N);

    for (int end = 0; end < size / 16; end++) {
        cleanbuffer(state);
        //get state data
        for (i = 0; i < 16; i++) {
            fread(state + i, 1, 1, origin_data);
        }

        //check the final bit index
        if (end == (size / 16) - 1) {
            fread( & index, 1, 1, key);
            if (index == 0) {
                index = 16;
            }
        }

        AES_decrypt(state, key_state, N, fast);
        fwrite(state, index, 1, output);
    }
}

//Cipher-block chaining encrypt
void CBC_de(char * file, char * keyfile, int fast) {
    int end_flag = 1, rekey = 1, exit_flag = 0, index = 16;
    int mode, i, N, keylen, size;
    unsigned char * state, * key_state, * IV, * temp_IV;
    FILE * origin_data = fopen(file, "r+");
    FILE * output = fopen("de_Output", "w");
    FILE * key;
    FILE * Initial_Vector;

    //get file size
    fseek(origin_data, 0, SEEK_END);
    size = ftell(origin_data);
    fseek(origin_data, 0, SEEK_SET);

    printf("\n(1)128\n(2)192\n(3)256\n");
    printf("Key length:");
    scanf("%d", & keylen);

    Initial_Vector = fopen("IV", "r");
    temp_IV = (char * ) malloc(sizeof(char) * 16);
    IV = (char * ) malloc(sizeof(char) * 16);
    fread(IV, 16, 1, Initial_Vector);

    switch (keylen) {
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

    key_state = (char * ) malloc(sizeof(char * ) * 16 * (7 + N));
    state = (char * ) malloc(sizeof(char) * 16);

    key = fopen(keyfile, "r");
    fread(key_state, N * 4, 1, key);

    KeySchedule(key_state, N);

    for (int end = 0; end < size / 16; end++) {
        cleanbuffer(state);

        //get state data
        for (i = 0; i < 16; i++) {
            fread(state + i, 1, 1, origin_data);
        }

        //check the final bit index
        if (end == (size / 16) - 1) {
            fread( & index, 1, 1, key);
            if (index == 0) {
                index = 16;
            }
        }

        for (i = 0; i < 16; i++) {
            *(temp_IV + i) = * (state + i);
        }
        AES_decrypt(state, key_state, N, fast);
        for (i = 0; i < 16; i++) {
            *(state + i) = * (IV + i) ^ * (state + i);
        }
        fwrite(state, index, 1, output);
        copy(IV, temp_IV);
    }
}

//Counter mode encrypt
void CTR_de(char * file, char * keyfile, int fast) {
    int end_flag = 1, rekey = 1, exit_flag = 0, index = 16;
    int i, N, keylen, size;
    unsigned char * state, * state_8, * key_state, * IV, * temp_IV, test = 1;
    FILE * origin_data = fopen(file, "r+");
    FILE * output = fopen("de_Output", "w");
    FILE * key;
    FILE * Initial_Vector;
    
    //get file size
    fseek(origin_data, 0, SEEK_END);
    size = ftell(origin_data);
    fseek(origin_data, 0, SEEK_SET);
    
    Initial_Vector = fopen("IV", "r");
    temp_IV = (char * ) malloc(sizeof(char) * 16);
    IV = (char * ) malloc(sizeof(char) * 16);
    fread(IV, 16, 1, Initial_Vector);

    printf("\n(1)128\n(2)192\n(3)256\n");
    printf("Key length:");

    scanf("%d", & keylen);
    switch (keylen) {
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

    key_state = (char * ) malloc(sizeof(char * ) * 16 * (7 + N));
    state = (char * ) malloc(sizeof(char) * 16);

    key = fopen(keyfile, "r");
    fread(key_state, N * 4, 1, key);
    KeySchedule(key_state, N);

    for (int end = 0; end < size / 16; end++) {
        cleanbuffer(state);

        //get state data
        for (i = 0; i < 16; i++) {
            fread(state + i, 1, 1, origin_data);
        }

        //check the final bit index
        if (end == (size / 16) - 1) {
            fread( & index, 1, 1, key);
            if (index == 0) {
                index = 16;
            }
        }
        copy(temp_IV, IV);
        AES_encrypt(IV, key_state, N, fast);

        for (i = 0; i < 16; i++) {
            *(state + i) = * (state + i) ^ * (IV + i);
        }

        fwrite(state, index, 1, output);
        copy(IV, temp_IV);

        for (i = 15; i >= 0; i--) {
            if ( * (IV + i) == 0xff) {
                *(IV + i) = 0x00;
            } else {
                *(IV + i) += 1;
                break;
            }
        }
    }
}

//Cipher feedback 8bit encrypt
void CFB_8_de(char * file, char * keyfile, int fast) {
    int end_flag = 1, exit_flag = 0, times = 16;
    int i, j, N, keylen, index, size;
    unsigned char * IV, * temp_IV, * state, * key_state;
    FILE * origin_data = fopen(file, "r+");
    FILE * output = fopen("de_Output", "w");
    FILE * key;
    FILE * Initial_Vector;

    //get file size
    fseek(origin_data, 0, SEEK_END);
    size = ftell(origin_data);
    fseek(origin_data, 0, SEEK_SET);

    printf("\n(1)128\n(2)192\n(3)256\n");
    printf("Key length:");

    scanf("%d", & keylen);
    switch (keylen) {
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

    key_state = (char * ) malloc(sizeof(char * ) * 16 * (7 + N));
    state = (char * ) malloc(sizeof(char) * 16);

    key = fopen(keyfile, "r");
    fread(key_state, N * 4, 1, key);
    KeySchedule(key_state, N);

    Initial_Vector = fopen("IV", "r");
    temp_IV = (char * ) malloc(sizeof(char) * 16);
    IV = (char * ) malloc(sizeof(char) * 16);

    fread(IV, 16, 1, Initial_Vector);
    copy(temp_IV, IV);

    for (int end = 0; end < size / 16; end++) {
        cleanbuffer(state);

        //get state data
        for (i = 0; i < 16; i++) {
            fread(state + i, 1, 1, origin_data);
        }

        //check the final bit index
        if (end == (size / 16) - 1) {
            fread( & times, 1, 1, key);
            if (times == 0) {
                times = 16;
            }
        }

        for (i = 0; i < times; i++) {
            shift_8(temp_IV);
            *(temp_IV + 15) = * state;
            AES_encrypt(IV, key_state, N, fast);
            * state = * state ^ * IV;
            fwrite(state, 1, 1, output);
            shift_8(state);
            copy(IV, temp_IV);
        }
    }
    fclose(output);
    fclose(origin_data);
    fclose(key);
}

//Cipher feedback 1bit encrypt
void CFB_1_de(char * file, char * keyfile, int fast) {
    int end_flag = 1, exit_flag = 0, times = 16;
    int i, j, N, keylen, index, size;
    unsigned char * IV, * temp_IV, * state, * key_state, out = 0x00, test;
    FILE * origin_data = fopen(file, "r+");
    FILE * output = fopen("de_Output", "w");
    FILE * key;
    FILE * Initial_Vector;

    //get file size
    fseek(origin_data, 0, SEEK_END);
    size = ftell(origin_data);
    fseek(origin_data, 0, SEEK_SET);

    printf("\n(1)128\n(2)192\n(3)256\n");
    printf("Key length:");
    scanf("%d", & keylen);
    switch (keylen) {
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

    key_state = (char * ) malloc(sizeof(char * ) * 16 * (7 + N));
    state = (char * ) malloc(sizeof(char) * 16);

    key = fopen(keyfile, "r");
    fread(key_state, N * 4, 1, key);
    KeySchedule(key_state, N);

    Initial_Vector = fopen("IV", "r");
    temp_IV = (char * ) malloc(sizeof(char) * 16);
    IV = (char * ) malloc(sizeof(char) * 16);

    fread(IV, 16, 1, Initial_Vector);
    copy(temp_IV, IV);

    for (int end = 0; end < size / 16; end++) {
        cleanbuffer(state);

        //get state data
        for (i = 0; i < 16; i++) {
            fread(state + i, 1, 1, origin_data);
        }

        //check the final bit index
        if (end == (size / 16) - 1) {
            fread( & times, 1, 1, key);
            if (times == 0) {
                times = 16;
            }
        }

        for (i = 1; i <= times * 8; i++) {
            AES_encrypt(IV, key_state, N, fast);
            * IV = * state ^ * IV;
            test = * state & 0x80;
            shift_1(temp_IV);

            if (test == 0x00) {
                *(temp_IV + 15) = * (temp_IV + 15) & 0xfe;
            } else {
                *(temp_IV + 15) = * (temp_IV + 15) | 0x01;
            }

            if (i % 8 != 0) {
                * IV = * IV >> 7;
                out = out | * IV;
                out = out << 1;
            } else {
                * IV = * IV >> 7;
                out = out | * IV;
            }
            if (i % 8 == 0) {
                fwrite( & out, 1, 1, output);
                out = 0x00;
            }

            copy(IV, temp_IV);
            shift_1(state);
        }
    }
}

//Output feedback feedback 8bit encrypt
void OFB_8_de(char * file, char * keyfile, int fast) {
    int end_flag = 1, exit_flag = 0, times = 16;
    int i, j, N, keylen, index, size;
    unsigned char * IV, * temp_IV, * state, * key_state;
    FILE * origin_data = fopen(file, "r+");
    FILE * output = fopen("de_Output", "w");
    FILE * key;
    FILE * Initial_Vector;
    //get file size
    fseek(origin_data, 0, SEEK_END);
    size = ftell(origin_data);
    fseek(origin_data, 0, SEEK_SET);

    printf("\n(1)128\n(2)192\n(3)256\n");
    printf("Key length:");
    scanf("%d", & keylen);
    switch (keylen) {
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

    key_state = (char * ) malloc(sizeof(char * ) * 16 * (7 + N));
    state = (char * ) malloc(sizeof(char) * 16);

    key = fopen(keyfile, "r");
    fread(key_state, N * 4, 1, key);
    KeySchedule(key_state, N);

    Initial_Vector = fopen("IV", "r");
    temp_IV = (char * ) malloc(sizeof(char) * 16);
    IV = (char * ) malloc(sizeof(char) * 16);

    fread(IV, 16, 1, Initial_Vector);
    copy(temp_IV, IV);

    for (int end = 0; end < size / 16; end++) {
        cleanbuffer(state);

        //get state data
        for (i = 0; i < 16; i++) {
            fread(state + i, 1, 1, origin_data);
        }

        //check the final bit index
        if (end == (size / 16) - 1) {
            fread( & times, 1, 1, key);
            if (times == 0) {
                times = 16;
            }
        }

        for (i = 0; i < times; i++) {
            AES_encrypt(IV, key_state, N, fast);
            shift_8(temp_IV);
            *(temp_IV + 15) = * IV;
            * state = * state ^ * IV;
            fwrite(state, 1, 1, output);
            shift_8(state);
            copy(IV, temp_IV);
        }
    }
    fclose(output);
    fclose(origin_data);
    fclose(key);
}

//Output feedback feedback 1bit encrypt
void OFB_1_de(char * file, char * keyfile, int fast) {
    int end_flag = 1, exit_flag = 0, times = 16;
    int i, j, N, keylen, index, size;
    unsigned char * IV, * temp_IV, * state, * key_state, out = 0x00, test;
    FILE * origin_data = fopen(file, "r+");
    FILE * output = fopen("de_Output", "w");
    FILE * key;
    FILE * Initial_Vector;

    //get file size
    fseek(origin_data, 0, SEEK_END);
    size = ftell(origin_data);
    fseek(origin_data, 0, SEEK_SET);

    printf("\n(1)128\n(2)192\n(3)256\n");
    printf("Key length:");

    scanf("%d", & keylen);
    switch (keylen) {
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

    key_state = (char * ) malloc(sizeof(char * ) * 16 * (7 + N));
    state = (char * ) malloc(sizeof(char) * 16);

    key = fopen(keyfile, "r");
    fread(key_state, N * 4, 1, key);
    KeySchedule(key_state, N);

    Initial_Vector = fopen("IV", "r");
    temp_IV = (char * ) malloc(sizeof(char) * 16);
    IV = (char * ) malloc(sizeof(char) * 16);

    fread(IV, 16, 1, Initial_Vector);
    copy(temp_IV, IV);

    for (int end = 0; end < size / 16; end++) {
        cleanbuffer(state);

        //get state data
        for (i = 0; i < 16; i++) {
            fread(state + i, 1, 1, origin_data);
        }

        //check the final bit index
        if (end == (size / 16) - 1) {
            fread( & times, 1, 1, key);
            if (times == 0) {
                times = 16;
            }
        }
        for (i = 1; i <= times * 8; i++) {
            AES_encrypt(IV, key_state, N, fast);
            test = * IV & 0x80;
            * IV = * state ^ * IV;
            shift_1(temp_IV);
            if (test == 0x00) {
                *(temp_IV + 15) = * (temp_IV + 15) & 0xfe;
            } else {
                *(temp_IV + 15) = * (temp_IV + 15) | 0x01;
            }

            if (i % 8 != 0) {
                * IV = * IV >> 7;
                out = out | * IV;
                out = out << 1;
            } else {
                * IV = * IV >> 7;
                out = out | * IV;
            }
            if (i % 8 == 0) {
                fwrite( & out, 1, 1, output);
                out = 0x00;
            }
            copy(IV, temp_IV);
            shift_1(state);
        }
    }
}