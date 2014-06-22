/*
   computeModular.c
   Example Code for Lab 3 
   requires libssl libcrpypto
Ubuntu: Package libssl-dev required
Compilation: gcc computeModular.c -o computeModular -lssl -lcrypto 
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <sys/time.h>

#define	MAXDIGITS	1000		/* maximum number of input digits */
#define NUMBITS 1024            /* bit length */


int main(int argc, char **argv)
{
	BIGNUM *a;
	BIGNUM *b;
	BIGNUM *c;
	BIGNUM *n;
	BIGNUM *p;
	BN_CTX *t;
	char input_a[MAXDIGITS];
	char input_b[MAXDIGITS];
	char input_n[MAXDIGITS];
	char seed[MAXDIGITS];
	struct timeval start, end;

	t = BN_CTX_new();
	BN_CTX_init(t);

	a = BN_new();
	b = BN_new();
	c = BN_new();
	n = BN_new();
	p = BN_new();

	printf("Generate Random Prime p  \n ******  \n");

	// Seed
	printf("Input Seed :  ");
	fgets(seed, MAXDIGITS,stdin);

	RAND_seed(seed, strnlen(seed,MAXDIGITS));

	// Generate random prime

	BN_generate_prime_ex(p, NUMBITS, 0, NULL, NULL,NULL);

	printf("p = %s\n ****** \n",BN_bn2dec(p));

	printf("Modular exponentiation a^b mod n  \n ******  \n");

	// Input a, b, n

	printf("a=  ");
	fgets(input_a, MAXDIGITS,stdin); // includes \n


	printf("b=  ");
	fgets(input_b, MAXDIGITS,stdin); // includes \n


	printf("n=  ");
	fgets(input_n, MAXDIGITS,stdin); // includes \n

	// char arrays to BIGNUM

	BN_dec2bn(&a,input_a);
	BN_dec2bn(&b,input_b);
	BN_dec2bn(&n,input_n);

	gettimeofday(&start, NULL); // start time

	// c=a^b mod n

	BN_mod_exp(c,a,b,n,t);

	if (ERR_get_error() != 0) {
		printf("Error ! \n");
		exit(1);
	}


	gettimeofday(&end, NULL);   // end time


	printf("%s^%s mod %s = %s\n",BN_bn2dec(a),BN_bn2dec(b),BN_bn2dec(n), BN_bn2dec(c));

	printf("Time elapsed: %ld Microseconds  \n", (long) end.tv_usec - start.tv_usec); 

	return(0);
}
