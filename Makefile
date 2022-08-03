# Standard GCC Flags 
CC=gcc
CFLAGS=-Wall

# External libraries for compilation
FLAGS = -lelf -lcrypto -lcapstone -lm
LIBELF = libelf64

# Object files for main executable
OBJ1 = libelf64.o
OBJ2 = binscan.o
OBJ3 = open_analysis.o
OBJ4 = compare.o
OBJ5 = encrypt.o

# Binscan: Main executable target
BINSCAN = binscan

# Main executable target
all: $(BINSCAN)
$(BINSCAN): $(OBJ1) $(OBJ2) $(OBJ3) $(OBJ4) $(OBJ5)
	$(CC) $(CFLAGS) -o $(BINSCAN) $(OBJ1) $(OBJ2) $(OBJ3) $(OBJ4) $(OBJ5) $(FLAGS)

# Compile ELF-64 Binary Parsing
$(OBJ1): libelf64.c
	$(CC) $(CFLAGS) $(FLAGS) -c $< -o $(OBJ1)

# Compile Command-Line interface handler
$(OBJ2): binscan.c
	$(CC) $(CFLAGS) $(FLAGS) -c $< -o $(OBJ2)

# Compile Analysis File Opener
$(OBJ3): open_analysis.c
	$(CC) $(CFLAGS) $(FLAGS) -c $< -o $(OBJ3)

# Compile compare_characters NASM function
$(OBJ4): compare.s
	nasm -f elf64 compare.s

$(OBJ5): encrypt.c
	$(CC) $(CFLAGS) $(FLAGS) -c $< -o $(OBJ5) 

# Remove unnecessary object files
clean:
	rm *.o
