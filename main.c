#include <stdio.h>
#include <stdlib.h>
#include <time.h>       
#include "AES.h"
#include "Encrypt_mode.h"
#include "Decrypt_mode.h"


int main(int argc, char *argv[]){
    int mode,fast;
    srand(time(NULL));
    printf("AES t-box mode: (1)enable (2)disable:");
    scanf("%d",&fast);
    if(fast!=1 && fast!=2){
        printf("error input");
        return 0;
    }
    printf("(1)ECB\n(2)CBC\n(3)CTR\n(4)CFB-8\n(5)CFB-1\n(6)OFB-8\n(7)OFB-1\n");
    printf("Mode:");
    scanf("%d", &mode);
    if (argc == 1){
        printf("Input one argument for encryption or two for decryption!");
        return 0;
    }
    //argc=2 encrypt
    if (argc == 2){
        switch (mode){
        case 1:
            ECB_en(argv[1],fast);
            break;
        case 2:
            CBC_en(argv[1],fast);
            break;
        case 3:
            CTR_en(argv[1],fast);
            break;
        case 4:
            CFB_8_en(argv[1],fast);
            break;
        case 5:
            CFB_1_en(argv[1],fast);
            break;
        case 6:
            OFB_8_en(argv[1],fast);
            break;
        case 7:
            OFB_1_en(argv[1],fast);
            break;
        default:
            printf("fail");
        }
    }
    //argc=3 decrypt
    if (argc == 3){
        switch (mode){
        case 1:
            ECB_de(argv[1], argv[2],fast);
            break;
        case 2:
            CBC_de(argv[1], argv[2],fast);
            break;
        case 3:
            CTR_de(argv[1], argv[2],fast);
            break;
        case 4:
            CFB_8_de(argv[1], argv[2],fast);
            break;
        case 5:
            CFB_1_de(argv[1], argv[2],fast);
            break;
        case 6:
            OFB_8_de(argv[1], argv[2],fast);
            break;
        case 7:
            OFB_1_de(argv[1], argv[2],fast);
            break;
        default:
            printf("fail");
        }
    }
}
