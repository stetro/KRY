
#include <string.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <sys/time.h>

#ifndef MAXDIGITS
#define MAXDIGITS 1000
#endif

#ifndef NUMBITS
#define NUMBITS 1024
#endif

#ifndef MAXLENGTH
#define MAXLENGTH 200
#endif


int main(int argc, char **argv){
	printf("RSA - Decrypt\n");
	printf("=============\n\n");

	if(argc < 3){
		printf("call with <sourcefile> <destinationfile> ");
		return EXIT_SUCCESS;
	}

	// get filename paths
	char * filenamePlaintext = argv[2];
	char * filenameCiphertext = argv[1];

	//Initialize RSA-Key and ask for d
	BIGNUM *d, *n, *e;
	d = BN_new();
	n = BN_new();
	e = BN_new();

	char text_d[MAXDIGITS];
	char text_n[MAXDIGITS];

	printf("Input modulus n:");
	fgets(text_n, MAXDIGITS, stdin);

	printf("Input private key d:");
	fgets(text_d, MAXDIGITS, stdin);

	BN_dec2bn(&d, text_d);
	BN_dec2bn(&n, text_n);
	BN_dec2bn(&e, "65537");

	RSA * myrsakey = RSA_new();
	myrsakey->n = n;
	myrsakey->d = d;
	myrsakey->e = e;

	// read file
	FILE *fileplain, *filecipher;
	filecipher = fopen(filenameCiphertext, "r+");
	fileplain = fopen(filenamePlaintext, "w+");
	if(filecipher == NULL){
		printf("File not found!");
		return EXIT_SUCCESS;
	}

	unsigned char plain_data[MAXLENGTH], cipher_data[256];
	int length = fread(cipher_data, 1, 256, filecipher);

	printf("\ndecrypting %d bytes\n",length);

	int enc_size = RSA_private_decrypt(length, cipher_data, plain_data, myrsakey, RSA_PKCS1_OAEP_PADDING);

	if(enc_size == -1){
		printf("\nError ! \n");
		ERR_print_errors_fp(stdout);
		return EXIT_FAILURE;
	}

	printf("%s", plain_data);

	int outlength = fwrite(plain_data,1,enc_size,fileplain);
	fclose(fileplain);
	fclose(filecipher);
	return EXIT_SUCCESS;
}

