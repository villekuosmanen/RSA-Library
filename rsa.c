#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <math.h>
#include <time.h>
#include <string.h>

#include "rsa.h"


char buffer[1024];
const int MAX_DIGITS = 50;
//const int MAX_THREE_BYTE_VALUE = 16777215;
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
  }
  if( e % 2 == 1){
    return ( b * rsa_modExp(b, (e-1), m) % m );
  }

}

char* rsa_encrypt(const char *message, const unsigned long message_size, const struct public_key_class *pub) {
    int no_of_chunks;
    if (message_size % 4) {
        no_of_chunks = (message_size / 4) + 1;  //Chunks of four, plus the remainder
    } else {
        no_of_chunks = (message_size / 4);
    }
    
    unsigned char* encrypted = malloc(no_of_chunks * sizeof(char) * 4);
    if(encrypted == NULL){
        fprintf(stderr, "Error: Heap allocation failed.\n");
        return NULL;
    }
    for(int i = 0; i < message_size; i += 4){
        // char firstChar = message[i];
        // char secondChar = i+1 < message_size ? message[i+1] : '\0';
        // char thirdChar = i+2 < message_size ? message[i+2] : '\0';
        // char fourthChar = i+3 < message_size ? message[i+3] : '\0';
        // printf("%c, %c, %c, %c\n", firstChar, secondChar, thirdChar, fourthChar);
        
        // int valueToEncrypt = (int) fourthChar + 255 * (int)thirdChar + 255*255 * (int)secondChar + 255*255*255 * (int)firstChar;
        int valueToEncrypt = *((int *) message + i); //Cast to a pointer and dereference
                //https://stackoverflow.com/questions/9165352/get-int-from-char-of-bytes

        printf("Value: %d\n", valueToEncrypt);
        unsigned int encryptedValue = rsa_modExp(valueToEncrypt, pub->exponent, pub->modulus);
        printf("Raw val (enc): %d\n", encryptedValue);
        //printf("Value: %d\n", encryptedValue);
        // if (encryptedValue > MAX_THREE_BYTE_VALUE) {
        //     fprintf(stderr, "Error: Too big value to encrypt, %d\n", encryptedValue);
        //     return NULL;
        // }
        //int index = i / 4;
        //encrypted[index] = encryptedValue;
        //After encryption
        encrypted[i] = (encryptedValue >> 24) & 0xFF;
        encrypted[i+1] = (encryptedValue >> 16) & 0xFF;
        encrypted[i+2] = (encryptedValue >> 8) & 0xFF;
        encrypted[i+3] = encryptedValue & 0xFF;

        //sprintf(encrypted + i,"%d", encryptedValue);    //BROKEN! Write this in binary
        printf("Written: %xd\n", *((int *) encrypted + i));
        int firstChar = encryptedValue/(255*255*255);
        int secondChar = (encryptedValue / (255*255)) % 255;
        int thirdChar = (encryptedValue / 255) % 255;
        int fourthChar = encryptedValue % 255;
        printf("Chars: %d, %d, %d, %d\n", (int)firstChar, (int)secondChar, (int)thirdChar, (int)fourthChar);
        // encrypted[i] = firstChar;
        // encrypted[i+1] = secondChar;
        // encrypted[i+2] = thirdChar;
        // encrypted[i+3] = fourthChar;
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
    // We allocate space to do the decryption (temp) and space for the output as a char array
    // (decrypted)
    char *decrypted = malloc(message_size);
    if(decrypted == NULL) {
        fprintf(stderr, "Error: Heap allocation failed.\n");
        return NULL;
    }
    // Now we go through each 4-byte chunk and decrypt it.
    for(int i = 0; i < message_size; i += 4){
        char firstChar = message[i];
        char secondChar = message[i+1];
        char thirdChar = message[i+2];
        char fourthChar = message[i+3];
        printf("Chars: %d, %d, %d, %d\n", (int)firstChar, (int)secondChar, (int)thirdChar, (int)fourthChar);
        
        int valueToDecrypt = *((int *) message + i);
        // int valueToDecrypt = (int) fourthChar + 255 * (int)thirdChar + 255*255 * (int)secondChar + 255*255*255 * (int)firstChar;
        printf("Raw val (decr): %d\n", valueToDecrypt);
        int decryptedValue = rsa_modExp(valueToDecrypt, priv->exponent, priv->modulus);
        printf("Value: %d\n", decryptedValue);
        // if (decryptedValue > MAX_THREE_BYTE_VALUE) {
        //     fprintf(stderr, "Error: Too big value to encrypt.\n");
        //     return NULL;
        // }
        //After encryption
        sprintf(decrypted + i,"%d", decryptedValue);
        // firstChar = decryptedValue/(255*255*255);
        // secondChar = (decryptedValue / (255*255)) % 255;
        // thirdChar = (decryptedValue / 255) % 255;
        // fourthChar = decryptedValue % 255;
        // printf("%c, %c, %c, %c\n", firstChar, secondChar, thirdChar, fourthChar);
        // decrypted[i] = firstChar;
        // decrypted[i+1] = secondChar;
        // decrypted[i+2] = thirdChar;
        // decrypted[i+3] = fourthChar;
    }
    return decrypted;
}
