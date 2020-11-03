
/*libelf parsing adapted from source code generated by Joseph Koshy for "libelf by Example".
  For more information please visit https://sourceforge.net/projects/elftoolchain/files/Documentation/libelf-by-example/*/
#include "bin/libelf64.h"
#include "bin/binproto.h"

#include <stdio.h> 
#include <stdint.h> 
#include <stdlib.h> 

#include <unistd.h> 
#include <fcntl.h>
#include <string.h>

#include <capstone/capstone.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <math.h>

int checkElf64(Elf *e){
  int i;
  if ((i = gelf_getclass(e)) == ELFCLASSNONE)
    errx(EXIT_FAILURE , "getclass() failed: %s.",elf_errmsg(-1));
  if(i == ELFCLASS32){ //ELF-32 object
	return 0;
  } else return 1; //ELF-64 object
}

Elf *openELF(char *file, int fd){
  Elf *e; 
  if ((e = elf_begin(fd, ELF_C_READ, NULL)) == NULL) errx(EXIT_FAILURE , "elf_begin() failed: %s.",elf_errmsg(-1)); 
  if (elf_kind(e) != ELF_K_ELF) errx(EXIT_FAILURE , "\"%s\" is not an ELF-64 object.", file); //Another check for ELF-64 object.
  return e; 
}

GElf_Shdr findTextSection(Elf *e, Elf_Scn **s){
  char *name = ""; //Section name
  size_t shstrndx; //Section header table index
  GElf_Shdr shdr; //Section header
  
  if (elf_getshdrstrndx(e, &shstrndx) != 0) errx(EXIT_FAILURE, "elf_getshdrstrndx() failed: %s.", elf_errmsg(-1)); //Get section header table index
  *s = NULL;
  while ((*s = elf_nextscn(e,*s)) != NULL){ //Find ".text" section by name                                                                                                                                       
    if (gelf_getshdr(*s, &shdr) != &shdr) errx(EXIT_FAILURE, "getshdr() failed: %s.", elf_errmsg(-1)); //Get section header

    if((name = elf_strptr (e,shstrndx,shdr.sh_name)) == NULL) //Get section name
      errx(EXIT_FAILURE, "elf_strptr() failed: %s.", elf_errmsg ( -1));

    if(strcmp(name, ".text") == 0){ break; } //Name is .text? 
  } return shdr; //Return section header
}

IBuffer printInstructions(unsigned char* buffer, size_t buffersize, uint64_t address){
  /************************************* PARSE INSTRUCTIONS *****************************************************/
  /*Adapted from Capstone Library C Demonstration.
    For more information visit https://www.capstone-engine.org/lang_c.html*/
  
  csh handle;
  cs_insn *insn; //Capstone instruction object pointer
  size_t count; //Number of instructions
  IBuffer ib; //Instruction buffer
  ib.ninstructions = 0; //Number of instructions
  /*From Project 1 2019 Demo*/
  if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle)) { //Initialize Capstone x86-64 disassembly
    printf("ERROR: Failed to initialize engine!\n");
    return ib;
  }
  
  count = cs_disasm(handle, buffer, buffersize, address, 0, &insn); //Pass buffer argument, size, section address to start disassembly
  int isUnique = 1; //is this instruction unique? 
  printf("%lu instructions\n\n", count); //Print number of instructions
  if (count){ //Count > 0?
    for (size_t j = 0; j < count; j++) { //Iterate over instructions 
      isUnique = 1; //Unique instruction flag
      for(size_t is = 0; is < ib.ninstructions; is++){
	if(strcmp(ib.instructions[is].instruction, insn[j].mnemonic) == 0) isUnique = 0; //See if instruction already in buffer
      }
      
      if(isUnique){ //Unique instruction -- add to buffer
	strcpy(ib.instructions[ib.ninstructions].instruction, insn[j].mnemonic);
	ib.ninstructions++;
      }
    }

    for(size_t m = 0; m < ib.ninstructions; m++){ //Iterate over instructions
      ib.instructions[m].instruction_calls = 1;
      for(size_t j = 0; j < count; j++){ //Count how many calls to instruction i
	if(strcmp(ib.instructions[m].instruction, insn[j].mnemonic) == 0) ib.instructions[m].instruction_calls++;
      } printf("%s\t%d\n", ib.instructions[m].instruction, ib.instructions[m].instruction_calls);
    }
    cs_free(insn, count); //Free capstone instruction object pointer
  }
  else {
    printf("ERROR: Failed to disassemble given code!\n");
  }  cs_close(&handle);

  return ib; //Return instruction buffer
}

IBuffer parseSectionText(Elf *e){
  Elf_Scn *scn; //Section pointer
  Elf_Data *data; //Section data
  GElf_Shdr shdr; //Section header
  IBuffer instructions; //Instruction buffer
  
  shdr = findTextSection(e,&scn); //Find text section header and section pointer
  data = NULL; 
  data = elf_getdata(scn, data); //Get data from .text section
  
  printf(".text\n");
  printf("Section starts at 0x%lx\n", shdr.sh_addr);
  printf("Section length: 0x%lx\n", shdr.sh_size);
  
  byte *p;
  p = (byte *)data->d_buf;
  instructions = printInstructions(p, data->d_size, shdr.sh_addr); //Print instructions in section
  return instructions; //Return instruction buffer
}

SHA256Record printSHA256(Elf *e){
  SHA256Record record; //SHA256 checksum
  Elf_Scn *scn;
  Elf_Data *data;
  SHA256_CTX shactx;

  SHA256_Init(&shactx);
  
  findTextSection(e, &scn);
  data = NULL;
  data = elf_rawdata(scn, data); //Retrieve raw byte data of .text section
  byte *p = (byte *) data->d_buf; //Make byte pointer of data buffer pointer
  while(p < (byte *) (data->d_buf + data->d_size)){
    SHA256_Update(&shactx, p, sizeof(byte)); //Update checksum
    p++;
  } SHA256_Final(record.sha256, &shactx);  //Finish checksum
  
  printf("SHA256: ");
  for(int i = 0; i < SHA256_DIGEST_LENGTH; i++){
    printf("%02x", record.sha256[i]); //Print checksum
  } printf("\n");

  return record; //Return SHA256 record
}

void printSHA1(Elf *e, byte *sha_value){
  Elf_Scn *scn;
  Elf_Data *data;
  SHA_CTX sha1ctx;  
  
  
  findTextSection(e, &scn); 
  data = NULL;
  data = elf_rawdata(scn, data); //Retrieve raw byte data of .text section
  byte *p = (byte *) data->d_buf; //Make byte pointer of data buffer pointer
  SHA1_Init(&sha1ctx);
  
  /*SHA1 Hash Calculation adapted from EVP Library Demonstration by Steve Tate.
   For more information visit https://www.uncg.edu/cmp/faculty/srtate/580.f11/sha1examples.php*/
  
  while(p < (byte *) (data->d_buf + data->d_size)){
    //UPDATE SHA1 Hash variable
   SHA1_Update(&sha1ctx, p, sizeof(byte));
   p++; 
  } SHA1_Final(sha_value, &sha1ctx); //Finalize checksum
  
  printf("SHA1: ");
  for(int i = 0; i < SHA_DIGEST_LENGTH; i++){
    printf("%02x", sha_value[i]); //Print SHA1 checksum
  } printf("\n");
}

int containsByte(byte *array, int length, byte b){
  if (length == 0){ return 0; } //Empty array
  for(int i = 0; i < length; i++){
    if(array[i] == b) return 1;  //Byte in array
  } return 0; 
}

RenyiEntropy calculateEntropy(Elf *e){
  RenyiEntropy r;  //Entropy value
  
  Elf_Scn *scn;
  Elf_Data *data;
  byte* start, *next;
  findTextSection(e, &scn);
  data = NULL; data = elf_rawdata(scn, data);

  double num_bytes = 0; //Number of bytes in .text section
  start = data->d_buf; //Point to start of section data
  while(start < (byte*) (data->d_buf + data->d_size)){
    start++; num_bytes++;
  } printf("%d bytes in section .text\n", (int) num_bytes);

  int byteschecked = 0; //Number of bytes checked
  byte textBytes[(int) num_bytes]; //Array of unique bytes

  double frequency = 0; //Frequency of byte being checked
  double probability_sum = 0.0;//Ongoing sum of byte probabilities
  start = data->d_buf;

  while(start < (byte *) (data->d_buf + data->d_size)){
    if(!containsByte(textBytes, byteschecked, *start)){ //Unique byte? frequency not already parsed
      next = start;
      next++;
      frequency = 1; 
      while(next < (byte *) (data->d_buf + data->d_size)){
	if(*next == *start){ //Count frequency of byte
	  frequency++;
	} next++; 
      }
      
      probability_sum += pow((frequency/num_bytes),2); //Add squared probability to sum
      start++;
    } 
  }
  
  r.entropy = log(probability_sum) / log(256); //log256(probabilitysum)
  if(r.entropy < 0.0) r.entropy *= -1; //Make sure entropy is positive
  
  printf("Renyi Entropy: %lf\n", r.entropy); //Print entropy
  return r; //Return entropy struct
}

/*fillFileBuffer adapted from Project 1 Example from 2019 given.*/
int fillFileBuffer(uint8_t *buffer, char *argfile, uint8_t *sha1){
  uint8_t *bptr = buffer; //Write file header to outfile
  strncpy(((FileHeader *)buffer)->file_name, argfile, sizeof(((FileHeader *)buffer)->file_name)-1);
  bptr += sizeof(FileHeader);

  ((SHA1Record *)bptr)->et = SHA1_RECORD; //Write SHA1Record to outfile
  memcpy(&((SHA1Record *)bptr)->sha1, sha1, sizeof((SHA1Record *)bptr)->sha1);
  ((FileHeader *)buffer)->data_length += sizeof(SHA1Record);
  bptr += sizeof(SHA1Record);
  return sizeof(FileHeader) + ((FileHeader *)buffer)->data_length;
}



/*
  Procedure:
  
  1. Open ELF-64 argument from file
  2. Calculate and print SHA1 Hash for .text section byte data
  3. Parse '.text' section data for instructions
  4. Print unique instructions with amount of calls 
  5. Calculate Renyi Entropy for bytes of text section
  6. Calculate and print SHA256 Hash for .text section byte data
  7. Write contents to '[argfile].bin' 
*/

void parseElf(char *file) {
  int fd;
  Elf *e;
  char *outputfile;
  FILE *outfile;
  
  uint8_t buffer[0x5000]; //Outfile buffer
  int recordsize; //Size of outfile buffer

  IBuffer ib; 
  RenyiEntropy r; 
  SHA256Record rsha256;
  byte sha1[SHA_DIGEST_LENGTH];
  
  if (elf_version(EV_CURRENT) == EV_NONE) errx(EXIT_FAILURE , "ELF library initialization failed: %s", elf_errmsg(-1));

  if ((fd = open(file, O_RDONLY, 0)) < 0)
    err(EXIT_FAILURE , "open \"%s\" failed", file);

  
  e = openELF(file, fd);
  if(!checkElf64(e)) printf("%s is not an ELF-64 object.\n\n", file);

  //Print SHA1 Hash of .text section
  printSHA1(e, sha1);
  printf("\n");

  //Print unique instructions with call counts
  ib = parseSectionText(e);
  printf("\n");

  //Print Renyi Entropy of .text section
  r = calculateEntropy(e); 

  //Print SHA256 Checksum of .text section
  rsha256 = printSHA256(e);
  
  //Close ELF Object, File
  elf_end(e);
  close(fd);
  
  //Generate output file name from file argument
  outputfile = malloc(strlen(file) + strlen(".bin")) + 1;
  outputfile[0] = '\0';

  strcat(outputfile, file);
  strcat(outputfile, ".bin");

  printf("Saving analysis to %s ..\n\n", outputfile); 
  
  //Write contents to file
  recordsize = fillFileBuffer(buffer, file, sha1);
  outfile = fopen(outputfile, "ab+");

  //SHA1 and File Header
  fwrite(buffer, sizeof(uint8_t), recordsize, outfile);

  //Instruction buffer
  fwrite(&ib, sizeof(IBuffer), 1, outfile);

  //Renyi Entropy
  fwrite(&r, sizeof(RenyiEntropy), 1, outfile); 

  //SHA256 Record
  fwrite(&rsha256, sizeof(SHA256Record), 1, outfile); 
  
  //Flush and close output file
  fflush(outfile);
  fclose(outfile);
  exit(EXIT_SUCCESS);
}

