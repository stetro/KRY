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


int main(int argc, char **argv){
	printf("RSA - Computation\n");
	printf("=================\n\n");

	printf("ENCRIPTION: \n");
	printf("===========\n\n");

	//Initialize random generator with seed
	printf("Initialize random generator with seed ... \n");
	char seed[MAXDIGITS];
	printf("Input Seed:");
	fgets(seed, MAXDIGITS, stdin);
	RAND_seed(seed, strnlen(seed, MAXDIGITS));

	// input plaintext as numper
	char text_plaintext[MAXDIGITS];
	BIGNUM *plaintext, *ciphertext;

	ciphertext = BN_new();
	plaintext = BN_new();
	printf("Input Plaintext:");
	fgets(text_plaintext, MAXDIGITS, stdin);
	BN_dec2bn(&plaintext, text_plaintext);

	//Measure time
	struct timeval stop, start;
	gettimeofday(&start, NULL);

	// Generate 2 random primes
	BIGNUM *p, *q, *e, *n;
	p = BN_new();
	q = BN_new();
	BN_generate_prime_ex(p, NUMBITS, 0, NULL, NULL, NULL);
	BN_generate_prime_ex(q, NUMBITS, 0, NULL, NULL, NULL);
	// Set e to 65537
	e = BN_new();
	BN_dec2bn(&e, "65537");

	// compute  n = pq
	BN_CTX *t;
	t = BN_CTX_new();
	BN_CTX_init(t);
	n = BN_new();
	BN_mul(n,p,q,t);

	if (ERR_get_error() != 0) {
		printf("Error ! \n");
		exit(1);
	}

	// compute phi_n = (q-1)(p-1)
	BIGNUM *q_minus_1, *p_minus_1, *one, *d, *phi_n;
	one = BN_new();
	q_minus_1 = BN_new();
	p_minus_1 = BN_new();
	phi_n = BN_new();
	d = BN_new();
	BN_dec2bn(&one, "1");
	BN_sub(q_minus_1, q, one);
	BN_sub(p_minus_1, p, one);
	BN_mul(phi_n ,p_minus_1, q_minus_1, t);

	// compute d with inverse of e mod phi_n
	BN_mod_inverse(d, e, phi_n, t);

	// compute ciphertexttime_t start = time(NULL);
	int length=BN_mod_exp(ciphertext, plaintext, e, n, t);

	gettimeofday(&stop, NULL);
	printf("took %d microseconds for normal exponentiation\n", stop.tv_usec - start.tv_usec);

	// documentation
	printf("\nPlaintext = %s\n",BN_bn2dec(plaintext));
	printf("Ciphertext = %s\n ****** \n",BN_bn2dec(ciphertext));
	printf("Generate two random primes q and p ...\n");
	printf("p = %s\n",BN_bn2dec(p));
	printf("q = %s\n ****** \n",BN_bn2dec(q));
	printf("\nSet e to 65537 ...\n");
	printf("\nCompute modulus n = pq ...\n");
	printf("n = %s\n ****** \n",BN_bn2dec(n));
	printf("\nCompute private exponent d ... \n");
	printf("d = %s\n ****** \n",BN_bn2dec(d));

	printf("\n\nDECRYPTION: \n");
	printf("=========== \n");

	//Measure time
	gettimeofday(&start, NULL);


	// Preperation
	BIGNUM *cp,*cq,*dp,*dq,*mp,*mq,*x,*y,*m,*xp,*yq,*mqxp, *mpyq;
	cp = BN_new();
	cq = BN_new();
	dp = BN_new();
	dq = BN_new();
	mp = BN_new();
	mq = BN_new();
	x = BN_new();
	y = BN_new();
	m = BN_new();
	xp = BN_new();
	yq = BN_new();
	mqxp = BN_new();
	mpyq = BN_new();

	gettimeofday(&start, NULL);

	BN_mod(cp, ciphertext, p, t);
	BN_mod(cq, ciphertext, q, t);
	BN_mod(dp, d, p_minus_1, t);
	BN_mod(dq, d, q_minus_1, t);
	BN_mod_exp(mp, cp, dp, p, t);
	BN_mod_exp(mq, cq, dq, q, t);
	BN_mod_inverse(x, p, q, t);
	BN_mod_inverse(y, q, p, t);

	//m = mqxp+mpyq mod pq
	BN_mul(xp, x, p, t);
	BN_mul(yq, y, q, t);
	BN_mul(mqxp, mq, xp, t);
	BN_mul(mpyq, mp, yq, t);
	BN_mod_add(m, mqxp, mpyq, n, t);
	gettimeofday(&stop, NULL);
	printf("took %d microseconds for CRT \n", stop.tv_usec - start.tv_usec);

	gettimeofday(&start, NULL);

	BN_mod_exp(plaintext, ciphertext, d, n, t);
	gettimeofday(&stop, NULL);

	printf("took %d microseconds for normal exponentiation\n", stop.tv_usec - start.tv_usec);

	printf("\nPlaintext = %s\n",BN_bn2dec(m));

	return EXIT_SUCCESS;
}
