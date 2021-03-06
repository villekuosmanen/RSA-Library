#include <stdio.h>
#include "rsa.h"
#include <string.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
  struct public_key_class pub[1];
  struct private_key_class priv[1];

  // Example keys that work
  priv->modulus = 2239219757;
  priv->exponent = 1590384365;

  pub->modulus = 2239219757;
  pub->exponent = 65537;

  printf("Private Key:\n Modulus: %lld\n Exponent: %lld\n", (long long)priv->modulus, (long long) priv->exponent);
  printf("Public Key:\n Modulus: %lld\n Exponent: %lld\n", (long long)pub->modulus, (long long) pub->exponent);
  
  char message[] = "123abcxy";
  int i;

  printf("Original:\n");
  for(i=0; i < strlen(message); i++){
    printf("%c\n", message[i]);
  }  
  
  char* encrypted = rsa_encrypt(message, strlen(message), pub);
  if (!encrypted){
    fprintf(stderr, "Error in encryption!\n");
    return 1;
  }
  printf("Encrypted:\n");
//   for(i=0; i < strlen(message); i++){
//     printf("%d\n", encrypted[i]);
//   }  
  


  char *decrypted = rsa_decrypt(encrypted, strlen(encrypted), priv);
  if (!decrypted){
    fprintf(stderr, "Error in decryption!\n");
    return 1;
  }
  printf("Decrypted:\n");
  for(i=0; i < strlen(decrypted); i++){
    printf("%c\n", decrypted[i]);
  }
  
printf("Done\n");
//   free(encrypted);
//   free(decrypted);
  return 0;
}
