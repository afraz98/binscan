#include <stdio.h>
#include <openssl/evp.h>
#include <stdlib.h>
#include "bin/libelf64.h"
#include <string.h>
#include "bin/open_analysis.h"
#include "bin/encrypt.h" 

void print_help(){
  printf("Welcome to Binscan!\n\n");
  printf("Currently supported options:\n\n");

  printf("--help: Print information on binscan\n");
  printf("--analyze: Analyze ELF-64 binary. Requires file argument. Example call: ./binscan -analyze helloworld\n");
  printf("--open: Open binary file produced by analyze command. !! Password Authentication necessary !!\n");
  printf("--encrypt: Encrypt binary analysis file. Example call: ./binscan -encrypt helloworld.bin encrypt.bin\n");
  printf("--decrypt: Decrypt encrypted binary analysis file. Exmaple call ./binscan -decrypt encrypt.bin read.bin\n"); 
}

int main(int argc, char **argv){
  if(argc == 1){
    printf("Invalid arguments. Type './binscan -help' for more information.\n");
    exit(0);
  }
  
  if(strcmp(argv[1], "--analyze") == 0 && argc == 3) parse_elf(argv[2]); //Parse ELF-64 object
  else if(strcmp(argv[1], "--help") == 0) print_help(); //Print help for binscan utility
  else if(strcmp(argv[1], "--open") == 0) open_analysis(argv[2]); //Open binary file containing analysis
  else if(strcmp(argv[1], "--encrypt") == 0) encrypt_file(argv[2], argv[3]); //Encrypt analysis file with shift cipher
  else if (strcmp(argv[1], "--decrypt") == 0) decrypt_file(argv[2], argv[3]); //Decrypt encrypted analysis file 
  else printf("Invalid arguments. Type '--help' for more information.\n");
  return 0;
}
