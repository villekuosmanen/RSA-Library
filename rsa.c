#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <math.h>
#include <time.h>
#include <string.h>

#include "rsa.h"


char buffer[1024];
const int MAX_DIGITS = 50;
int i,j = 0;

// This should totally be in the math library.
long long gcd(long long a, long long b) {
  long long c;
  while ( a != 0 ) {
    c = a; a = b%a;  b = c;
  }
  return b;
}


long long ExtEuclid(long long a, long long b) {
 long long x = 0, y = 1, u = 1, v = 0, gcd = b, m, n, q, r;
 while (a!=0) {
   q = gcd/a; r = gcd % a;
   m = x-u*q; n = y-v*q;
   gcd = a; a = r; x = u; y = v; u = m; v = n;
   }
   return y;
}

long long rsa_modExp(unsigned long long b, unsigned long long e, unsigned long long m) {
    //printf("%lld, %lld, %lld\n", b, e, m);
  if (m <= 0){
    exit(1);
  }
  b = b % m;
  if(e == 0) return 1;
  if(e == 1) return b;
  if( e % 2 == 0){
    return ( rsa_modExp(b * b % m, e/2, m) % m );
  } else {
    return ( b * rsa_modExp(b, (e-1), m) % m );
  }

}

char* rsa_encrypt(const char *message, const unsigned long message_size, const struct public_key_class *pub) {
    int no_of_chunks;
    if (message_size % 3) {
        no_of_chunks = (message_size / 3) + 1;  //Chunks of three, plus the remainder
        char* temp = (char*) calloc(no_of_chunks * 3, 1);
        memcpy(temp, message, message_size);
        message = temp;
    } else {
        no_of_chunks = message_size / 3;
    }
    //printf("Chunks: %d\n", no_of_chunks);
    
    char* encrypted = (char*) malloc(no_of_chunks * sizeof(char) * 4); //Encrypted output is wider, chunks of four
    if(encrypted == NULL){
        fprintf(stderr, "Error: Heap allocation failed.\n");
        return NULL;
    }
    for(int i = 0; i < no_of_chunks; i++) {
        unsigned int valueToEncrypt = ((unsigned char*)message)[i*3] + (((unsigned char*)message)[i*3 + 1] << 8) + (((unsigned char*)message)[i*3 + 2] << 16);
                // https://stackoverflow.com/questions/9896589/how-do-you-read-in-a-3-byte-size-value-as-an-integer-in-c

        //printf("Value: %ud\n", valueToEncrypt);
        unsigned int encryptedValue = rsa_modExp(valueToEncrypt, pub->exponent, pub->modulus);
        //printf("Raw val (enc): %d\n", encryptedValue);

        // Converting an int to a bytes array (little-endian)
            // https://stackoverflow.com/questions/3784263/converting-an-int-into-a-4-byte-char-array-c
        encrypted[i*4 + 3] = (encryptedValue >> 24) & 0xFF;
        encrypted[i*4 + 2] = (encryptedValue >> 16) & 0xFF;
        encrypted[i*4 + 1] = (encryptedValue >> 8) & 0xFF;
        encrypted[i*4] = encryptedValue & 0xFF;
        //printf("Written: %d\n", *((int *) encrypted + i*4));
    }
    return encrypted;
}


char* rsa_decrypt(const char* message, 
                  const unsigned long message_size, 
                  const struct private_key_class *priv) {
    if(message_size % 4 != 0) {
        fprintf(stderr,
            "Error: message_size is not divisible by 4, so cannot be output of microbit rsa_encrypt\n");
        return NULL;
    }
    int no_of_chunks = message_size / 4;
    // We allocate space to do the decryption (temp) and space for the output as a char array
    // (decrypted)
    char *decrypted = (char*) malloc(no_of_chunks * 3);
    if(decrypted == NULL) {
        fprintf(stderr, "Error: Heap allocation failed.\n");
        return NULL;
    }
    // Now we go through each 4-byte chunk and decrypt it.
    for(int i = 0; i < no_of_chunks; i++){
        
        unsigned int valueToDecrypt = *((int *) (message + i*4));
        //printf("Raw val (decr): %d\n", valueToDecrypt);
        unsigned int decryptedValue = rsa_modExp(valueToDecrypt, priv->exponent, priv->modulus);
        //printf("Value (decr): %d\n", decryptedValue);

        //After encryption
        decrypted[i*3 + 2] = (decryptedValue >> 16) & 0xFF;
        decrypted[i*3 + 1] = (decryptedValue >> 8) & 0xFF;
        decrypted[i*3] = decryptedValue & 0xFF;
    }
    return decrypted;
}
