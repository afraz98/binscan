#include <stdio.h>
#include <stdlib.h>

#include "elf_parser.h"
#include "encrypt.h"

void encrypt_file(char *file, char *outputfile){
  FILE *input;
  FILE *output;

  int data;
  input = fopen(file, "rb");
  output = fopen(outputfile, "w");

  if(input != NULL && output != NULL){
    while((data = fgetc(input)) != EOF){
      data += 7;
      fputc(data, output); 
    }
  } else {
    printf("Error parsing file arguments for encryption");
    exit(0); 
  }
  
}

void decrypt_file(char *file, char *outputfile){
  FILE *input;
  FILE *output;
  
  int data;
  input = fopen(file, "rb");
  output = fopen(outputfile, "w");

  if(input != NULL && output != NULL){
    while((data = fgetc(input)) != EOF){
      data -= 7;
      fputc(data, output);
    }
  } else {
    printf("Error parsing file arguments for encryption");
    exit(0);
  }
}
  