#ifndef __RSA_H__
#define __RSA_H__

#include <stdint.h>

// This is the header file for the library librsaencrypt.a

// Change this line to the file you'd like to use as a source of primes.
// The format of the file should be one prime per line.
//char *PRIME_SOURCE_FILE = "smallPrimes.txt";


struct public_key_class {
  unsigned int modulus;
  unsigned int exponent;
};

struct private_key_class {
  unsigned int modulus;
  unsigned int exponent;
};

// This function will encrypt the data pointed to by message. It returns a pointer to a heap
// array containing the encrypted data, or NULL upon failure. This pointer should be freed when 
// you are finished.
char* rsa_encrypt(const char *message, const unsigned long message_size, const struct public_key_class *pub);

// This function will decrypt the data pointed to by message. It returns a pointer to a heap
// array containing the decrypted data, or NULL upon failure. This pointer should be freed when 
// you are finished. The variable message_size is the size in bytes of the encrypted message. 
char *rsa_decrypt(const char* message, const unsigned long message_size, const struct private_key_class *pub);

#endif
