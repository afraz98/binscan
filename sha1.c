/*
  Adapted from OpenSSL Demo Code on 'EVP_DigestInit'.
  For more information please visit https://www.openssl.org/docs/man1.0.2/man3/EVP_DigestInit.html
*/

#include "bin/libelf64.h"
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void printSHA1(int length, unsigned char* value){
  printf("SHA1: ");
  for(int i = 0; i < length; i++){
    printf("%02x", value[i]);
  } printf("\n");
}

int main(){
  EVP_MD_CTX *mdctx;
  const EVP_MD *md;
  char mess1[] = "Test Message\n";
  char mess2[] = "Hello World\n";
  unsigned char md_value[EVP_MAX_MD_SIZE];
  int md_len, i;
 
  OpenSSL_add_all_digests();
  md = EVP_get_digestbyname("SHA1");
  
  mdctx = EVP_MD_CTX_create();
  EVP_DigestInit_ex(mdctx, md, NULL);


  //Use elf_rawdata to get raw data from text section for this?
  EVP_DigestUpdate(mdctx, mess1, strlen(mess1));
  EVP_DigestUpdate(mdctx, mess2, strlen(mess2));

  EVP_DigestFinal_ex(mdctx, md_value, &md_len);
  EVP_MD_CTX_destroy(mdctx);
  printSHA1(md_len, md_value);
  
  /* Call this once before exit. */
  EVP_cleanup();
  exit(0);
}
