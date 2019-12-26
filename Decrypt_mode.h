void ECB_de(char *file, char *key,int fast);//Electronic codebook decrypt
void CBC_de(char *file, char *key,int fast);//Cipher-block chaining decrypt
void CTR_de(char *file, char *key,int fast);//Counter mode decrypt
void CFB_8_de(char *file, char *key,int fast);//Cipher feedback-8bit decrypt
void CFB_1_de(char *file, char *key,int fast);//Cipher feedback-1bit decrypt
void OFB_8_de(char *file, char *key,int fast);//Output feedback-8bit decrypt
void OFB_1_de(char *file, char *key,int fast);//Output feedback-1bit decrypt