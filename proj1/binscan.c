#include <stdio.h>
#include <openssl/evp.h>
#include <stdlib.h>
#include "bin/libelf64.h"

int main(int argc, char **argv){
  parseElf(argc, argv);
  return 0;
}
