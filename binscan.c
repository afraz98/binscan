#include <stdio.h>
#include <openssl/evp.h>
#include <stdlib.h>
#include "bin/libelf64.h"
#include <string.h>

void printHelp(){
  printf("Welcome to Binscan!\n\n");
  printf("Current supported options:\n\n");

  printf("-help: Print information on binscan\n");
  printf("-analyze: Analyze ELF-64 binary. Requires file argument. Example call: ./binscan -analyze binary\n"); 
}

int main(int argc, char **argv){
  if(argc == 1){
    printf("Invalid arguments. Type './binscan -help' for more information.\n");
    exit(0);
  }
  
  if(strcmp(argv[1], "-analyze") == 0 && argc == 3) parseElf(argv[2]);
  if(strcmp(argv[1], "-help") == 0) printHelp(); 
  return 0;
}
