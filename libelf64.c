#include "bin/libelf64.h"
#include "bin/bin_proto.h"

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

#define CODE "\x55\x48\x8b\x05\xb8\x13\x00\x00"

int check_elf64(Elf *e){
  int i;
  
  if ((i = gelf_getclass(e)) == ELFCLASSNONE)
    errx(EXIT_FAILURE , "getclass() failed: %s.",elf_errmsg(-1));
  
  if(i == ELFCLASS32)
	  // Not a valid ELF-64 object.
    return 0;
  
  // Valid ELF-64 object
  return 1;     
}

Elf* open_elf(char *file, int fd){
  Elf *e; 
  if ((e = elf_begin(fd, ELF_C_READ, NULL)) == NULL) errx(EXIT_FAILURE , "elf_begin() failed: %s.",elf_errmsg(-1)); 

  // Another check for ELF-64 object.
  if (elf_kind(e) != ELF_K_ELF) errx(EXIT_FAILURE , "\"%s\" is not an ELF-64 object.", file); 
  
  return e; 
}

GElf_Shdr find_text_section(Elf *e, Elf_Scn **s){
  // Section name
  char *name = "";  
  
  // Section header table index
  size_t shstrndx;  
  
  // Section header
  GElf_Shdr shdr;   
  
  // Get section header table index
  if (elf_getshdrstrndx(e, &shstrndx) != 0) errx(EXIT_FAILURE, "elf_getshdrstrndx() failed: %s.", elf_errmsg(-1)); 
  *s = NULL;
  
  // Find ".text" section by name
  while ((*s = elf_nextscn(e,*s)) != NULL){                                                            
    // Get section header                                                                                                                                       
    if (gelf_getshdr(*s, &shdr) != &shdr) errx(EXIT_FAILURE, "getshdr() failed: %s.", elf_errmsg(-1)); 

    // Get section name
    if((name = elf_strptr (e,shstrndx, shdr.sh_name)) == NULL) 
      errx(EXIT_FAILURE, "elf_strptr() failed: %s.", elf_errmsg ( -1));

    // name == '.text' ? 
    if(strcmp(name, ".text") == 0){ break; } 
  } 
  
  return shdr; // Return section header
}

IBuffer print_instructions(unsigned char* buffer, size_t buffer_size, uint64_t address){
  // Capstone handler object
  csh handle;

  // Capstone instruction object pointer
  cs_insn *insn;

  // Number of instructions
  size_t count;
  
  // Instruction buffer
  IBuffer ib;

  // Number of instructions
  ib.ninstructions = 0;   
  
  // Initialize Capstone x86-64 disassembly
  if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) { 
    printf("ERROR: Failed to initialize engine!\n");
    return ib;
  }
  
  // Pass buffer argument, size, section address to start disassembly
  count = cs_disasm(handle, buffer, buffer_size, address, 0, &insn); 
  
  // Is this instruction unique? 
  int isUnique = 1; 
  
  // Count > 0?
  if (count > 0){ 
    // Iterate over instructions 
    for (size_t j = 0; j < count; j++) {
      printf("0x%"PRIx64":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic, insn[j].op_str);

      // Unique instruction flag
      isUnique = 1;
      
      // See if instruction already in buffer
      for(size_t is = 0; is < ib.ninstructions; is++){
        if(strcmp(ib.instructions[is].instruction, insn[j].mnemonic) == 0) isUnique = 0; 
      }
      
      if(isUnique){
        // Unique instruction -- add to buffer
        strcpy(ib.instructions[ib.ninstructions].instruction, insn[j].mnemonic);
        ib.ninstructions++;
      }
    }

    printf("\n");
    
    // Iterate over instructions
    for(size_t m = 0; m < ib.ninstructions; m++){ 
      ib.instructions[m].instruction_calls = 0;
      
      for(size_t j = 0; j < count; j++){ 
        // Count calls to instruction i
	      if(strcmp(ib.instructions[m].instruction, insn[j].mnemonic) == 0) ib.instructions[m].instruction_calls++;
      } 
      
      printf("%s\t%d\n", ib.instructions[m].instruction, ib.instructions[m].instruction_calls);
    }

    // Free capstone instruction object pointer
    cs_free(insn, count); 
  } else {
    printf("ERROR: Failed to disassemble given code!\n");
  }  
  
  cs_close(&handle);
  return ib; // Return instruction buffer
}

IBuffer parse_text_section(Elf *e){
  Elf_Scn *scn_ptr;       // Section pointer
  Elf_Data *scn_data;     // Section data
  GElf_Shdr scn_hdr;      // Section header
  IBuffer instructions;   // Instruction buffer
  
  // Find text section header and section pointer
  scn_hdr = find_text_section(e, &scn_ptr); 
  
  // Get scn_data from .text section
  scn_data = elf_getdata(scn_ptr, scn_data);
  
  printf(".text\n");
  printf("Section starts at 0x%lx\n", scn_hdr.sh_addr);
  printf("Section length: 0x%lx\n\n", scn_hdr.sh_size);
  
  byte *p;
  p = (byte *)scn_data->d_buf;

  // Print instructions in section
  instructions = print_instructions(p, scn_data->d_size, scn_hdr.sh_addr); 
  
  // Return instruction buffer
  return instructions;                                              
}

SHA256Record print_sha256(Elf *e){
  SHA256Record record; //SHA256 checksum
  Elf_Scn *scn_ptr;
  SHA256_CTX shactx;
  SHA256_Init(&shactx);
  
  // Find .text section in binary
  find_text_section(e, &scn_ptr);

  // Retrieve raw byte scn_data of .text section
  Elf_Data *scn_data = elf_rawdata(scn_ptr, scn_data);
  
  // Cast scn_data buffer pointer to byte pointer
  byte *p = (byte *) scn_data->d_buf;
  
  while(p < (byte *) (scn_data->d_buf + scn_data->d_size)){
    // Update checksum
    SHA256_Update(&shactx, p, sizeof(byte)); 
    p++;
  } 

  // Finish checksum
  SHA256_Final(record.sha256, &shactx);  

  // Print checksum
  printf("SHA256: ");
  for(int i = 0; i < SHA256_DIGEST_LENGTH; i++){
    printf("%02x", record.sha256[i]);
  } 
  printf("\n");

  // Return SHA256 record
  return record; 
}

//Calculate and print SHA1 checksum of text section
void print_sha1(Elf *e, byte *sha_value){
  Elf_Scn *scn_ptr;
  Elf_Data *scn_data;
  SHA_CTX sha1ctx;  
  
  
  find_text_section(e, &scn_ptr); 
  scn_data = NULL;
  scn_data = elf_rawdata(scn_ptr, scn_data);  // Retrieve raw byte scn_data of .text section
  byte *p = (byte *) scn_data->d_buf; // Make byte pointer of scn_data buffer pointer
  SHA1_Init(&sha1ctx);
  
  while(p < (byte *) (scn_data->d_buf + scn_data->d_size)){
   // UPDATE SHA1 Hash variable
   SHA1_Update(&sha1ctx, p, sizeof(byte));
   p++; 
  } 
  
  SHA1_Final(sha_value, &sha1ctx); // Finalize checksum
  
  printf("SHA1: ");
  for(int i = 0; i < SHA_DIGEST_LENGTH; i++){
    printf("%02x", sha_value[i]); // Print SHA1 checksum
  } printf("\n");
}

// Check if byte array contains a certain byte 
int contains_byte(byte *array, int length, byte b){
  if (length == 0){ return 0; }  // Empty array
  for(int i = 0; i < length; i++){
    if(array[i] == b) return 1;  // Byte in array
  } return 0; 
}

// Calculate and print Renyi Entropy of text section
RenyiEntropy calculate_renyi_entropy(Elf *e){
  RenyiEntropy r;  //Entropy value
  
  Elf_Scn *scn_ptr;
  Elf_Data *scn_data;
  byte* start, *next;

  find_text_section(e, &scn_ptr);
  scn_data = NULL; scn_data = elf_rawdata(scn_ptr, scn_data);

  double num_bytes = 0; // Number of bytes in .text section
  start = scn_data->d_buf;  // Point to start of section scn_data
  while(start < (byte*) (scn_data->d_buf + scn_data->d_size)){
    start++; num_bytes++;
  } printf("%d bytes in section .text\n", (int) num_bytes);

  int byteschecked = 0;             // Number of bytes checked
  byte textBytes[(int) num_bytes];  // Array of unique bytes

  double frequency = 0;             // Frequency of byte being checked
  double probability_sum = 0.0;     // Ongoing sum of squared byte probabilities
  start = scn_data->d_buf;

  while(start < (byte *) (scn_data->d_buf + scn_data->d_size)){
    if(!contains_byte(textBytes, byteschecked, *start)){ //Unique byte? frequency not already parsed
      next = start;
      next++;
      frequency = 1; 
      while(next < (byte *) (scn_data->d_buf + scn_data->d_size)){
	if(*next == *start){ //Count frequency of byte
	  frequency++;
	} next++; 
      }
      
      probability_sum += pow((frequency/num_bytes),2); //Add squared probability to sum
      start++;
    } 
  }
  
  r.entropy = fabs(log(probability_sum) / log(256)); //|log256(probabilitysum)|
  printf("Renyi Entropy: %lf\n", r.entropy); //Print entropy
  return r; //Return entropy struct
}

// Write SHA1Record and File header to output file.
int fill_file_buffer(uint8_t *buffer, char *argfile, uint8_t *sha1){
  uint8_t *bptr = buffer; //Write file header to outfile
  strncpy(((FileHeader *)buffer)->file_name, argfile, sizeof(((FileHeader *)buffer)->file_name)-1);
  bptr += sizeof(FileHeader);

  ((SHA1Record *)bptr)->et = SHA1_RECORD; //Write SHA1Record to outfile
  memcpy(&((SHA1Record *)bptr)->sha1, sha1, sizeof((SHA1Record *)bptr)->sha1);
  ((FileHeader *)buffer)->data_length += sizeof(SHA1Record);
  bptr += sizeof(SHA1Record);
  return sizeof(FileHeader) + ((FileHeader *)buffer)->data_length;
}

// Main driver function
void parse_elf(char *file) {
  int fd;                 // File descriptor
  Elf *elf_ptr;           // ELF Object pointer
  char *output_filename;  // Output file name
  FILE *outfile;          // Output file object
  
  byte buffer[0x5000];    // Outfile buffer
  int record_size;         // Size of outfile buffer

  IBuffer ib;             // Instruction buffer
  RenyiEntropy r;         // Renyi entropy struct
  SHA256Record rsha256;   // SHA256 checksum struct
  byte sha1[SHA_DIGEST_LENGTH]; //SHA1 checksum byte array 
  
  if (elf_version(EV_CURRENT) == EV_NONE) errx(EXIT_FAILURE ,
					       "ELF library initialization failed: %s", elf_errmsg(-1)); //Verify libelf library current and functional

  if ((fd = open(file, O_RDONLY, 0)) < 0) //Open input file 
    err(EXIT_FAILURE , "open \"%s\" failed", file);

  // Retrieve ELF object from input file 
  elf_ptr = open_elf(file, fd);
  
  if(!check_elf64(elf_ptr)){
    // File is NOT in ELF-64 format
    printf("%s is not an ELF-64 object.\n\n", file);
    exit(0); 
  }

  // Print SHA1 Hash of .text section
  print_sha1(elf_ptr, sha1);
  printf("\n");

  // Print unique instructions with call counts
  ib = parse_text_section(elf_ptr);
  printf("\n");

  // Print Renyi Entropy of .text section
  r = calculate_renyi_entropy(elf_ptr); 

  // Print SHA256 Checksum of .text section
  rsha256 = print_sha256(elf_ptr);
  
  // Close ELF Object, File
  elf_end(elf_ptr);
  close(fd);
  
  // Generate output file name from file argument
  output_filename = malloc(strlen(file) + strlen(".bin")) + 1;
  output_filename[0] = '\0';

  strcat(output_filename, file);
  strcat(output_filename, ".bin");
  printf("Saving analysis to %s ..\n\n", output_filename); 
  
  // Write contents to file
  record_size = fill_file_buffer(buffer, file, sha1);
  outfile = fopen(output_filename, "ab+");

  // SHA1 and File Header
  fwrite(buffer, sizeof(uint8_t), record_size, outfile);

  // Instruction buffer
  fwrite(&ib, sizeof(IBuffer), 1, outfile);

  // Renyi Entropy
  fwrite(&r, sizeof(RenyiEntropy), 1, outfile); 

  // SHA256 Record
  fwrite(&rsha256, sizeof(SHA256Record), 1, outfile); 
  
  // Flush and close output file
  fflush(outfile);
  fclose(outfile);
  exit(EXIT_SUCCESS);
}


