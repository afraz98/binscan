#include <stdio.h>
#include <openssl/evp.h>
#include <stdlib.h>
#include <string.h>

#include "analysis_parser.h"
#include "elf_parser.h"
#include "encrypt.h" 

void print_help(){
  printf("Usage:\n");
  printf("--help: Print information on binscan\n");
  printf("--analyze: Analyze ELF-64 binary. Requires file argument. Example call: ./binscan --analyze helloworld\n");
  printf("--open: Open binary file produced by analyze command.\n");
  printf("--encrypt: Encrypt binary analysis file. Example call: ./binscan --encrypt helloworld.bin encrypt.bin\n");
  printf("--decrypt: Decrypt encrypted binary analysis file. Exmaple call ./binscan --decrypt encrypt.bin read.bin\n"); 
}

int main(int argc, char **argv){
  if(argc == 1){
    print_help();
    exit(0);
  }
  
  if(strcmp(argv[1], "--analyze") == 0 && argc == 3) parse_elf(argv[2]);        // Parse ELF-64 object
  else if(strcmp(argv[1], "--help") == 0) print_help();                         // Print help for binscan utility
  else if(strcmp(argv[1], "--open") == 0) parse_analysis(argv[2]);              // Open binary file containing analysis
  else if(strcmp(argv[1], "--encrypt") == 0) encrypt_file(argv[2], argv[3]);    // Encrypt analysis file with shift cipher
  else if (strcmp(argv[1], "--decrypt") == 0) decrypt_file(argv[2], argv[3]);   // Decrypt encrypted analysis file 
  else printf("Invalid arguments. Use '--help' for more information.\n");
  return 0;
}
