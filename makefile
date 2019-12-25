main:
	gcc -o main.out main.c AES.c Decrypt_mode.c Encrypt_mode.c bit_operation.c
clean:
	rm -f *.o
