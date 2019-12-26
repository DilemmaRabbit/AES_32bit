//encrypt functions
void AddRoundKey(unsigned char *state, unsigned char *key); //xor with key
void SubBytes(unsigned char *state);//replace with s-box
void ShiftRows(unsigned char *state);//shift state
void MixColumn(unsigned char *state);//mix with mix matrix

//decrypt functions(AddRoundKey is same as decrypt)
void InvSubBytes(unsigned char *state);     //replace with s-box
void InvMixColumn(unsigned char *state);    //mix with mix inv matrix
void InvShiftRows(unsigned char *state);    //shift state

//other operations
unsigned char Mix_mul2(unsigned char target);   //Gf2 multiple 2
void KeySchedule(unsigned char *key, int N);    //Generate key

//test function
void show(unsigned char *state);             //Show state matrix or IV 
void showkey(unsigned char *key, int N);     //Show all key(with N)

//main operation function
void AES_encrypt(unsigned char *state, char *key, int N);    //encrypt
void AES_decrypt(unsigned char *state, char *key, int N);    //decrypt

