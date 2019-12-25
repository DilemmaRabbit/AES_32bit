#include "bit_operation.h"

void cleanbuffer(unsigned char *buffer)
{
    for (int i = 0; i < 16; i++)
    {
        *(buffer + i) = 0x00;
    }
}

void copy(unsigned char *temp1,unsigned char *temp2){
    for(int i=0;i<16;i++){
        *(temp1+i) = *(temp2+i); 
    }
}

void shift_8(unsigned char *temp){
    for(int i=0;i<15;i++){
        *(temp+i) = *(temp+i+1);
    }
}

void shift_1(unsigned char *temp){
    unsigned char check = 0x80;
    unsigned char temp_8;
    for(int i=0;i<16;i++){
        if(i==0){
            *(temp+i) = *(temp+i) << 1;
        }
        else{
            temp_8 = *(temp+i) & check;
            if(temp_8==0x00){
                *(temp+i-1) = *(temp+i-1) & 0xfe;
            }
            else{
                *(temp+i-1) = *(temp+i-1) | 0x01;
            }
            *(temp+i) = *(temp+i) << 1;
        }
    }
}