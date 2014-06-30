#include <stdlib.h>
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

	printf("RSA - Encrypt\n");
	printf("=============\n\n");

	// get filename paths
	char * filenamePlaintext = argv[1];
	char * filenameCiphertext = argv[2];

	//Initialize RSA-Key and ask for n
	BIGNUM *e, *n;
	e = BN_new();
	n = BN_new();

	char text_n[MAXDIGITS];
	printf("Input modulus n:");
	fgets(text_n, MAXDIGITS, stdin);
	BN_dec2bn(&n, text_n);
	BN_dec2bn(&e, "65537");

	if(BN_num_bits(n) < 2000){
		printf("Error ! \n");
		return EXIT_FAILURE;
	}

	RSA * myrsakey = RSA_new();
	myrsakey->n = n;
	myrsakey->e = e;

	// read file
	FILE *fileplain, *filecipher;
	fileplain = fopen(filenamePlaintext, "r+");
	filecipher = fopen(filenameCiphertext, "w+");
	unsigned char input_data[MAXLENGTH], cipher_data[MAXLENGTH];
	int length = fread(input_data, 1, MAXLENGTH, fileplain);

	printf("\nencypting %d bytes\n",length);

	int enc_size = RSA_public_encrypt(length, input_data, cipher_data, myrsakey, RSA_PKCS1_OAEP_PADDING);

	if(enc_size == -1){
		printf("\nError ! \n");
		ERR_print_errors_fp(stdout);
		return EXIT_FAILURE;
	}

	int outlength = fwrite(cipher_data,1,enc_size,filecipher);
	printf("\n write %d bytes to %s \n", outlength ,filenameCiphertext);
	fclose(fileplain);
	fclose(filecipher);

	return EXIT_SUCCESS;

}
