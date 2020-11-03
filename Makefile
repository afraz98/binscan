CC=gcc
CFLAGS=-Wall
FLAGS = -lelf -lcrypto -lcapstone -lm
LIBELF = libelf64
OBJ1 = libelf64.o
OBJ2 = binscan.o
OBJ3 = openscan.o
OBJ4 = compare.o
BINSCAN = binscan

all: $(BINSCAN)

$(BINSCAN): $(OBJ1) $(OBJ2) $(OBJ3) $(OBJ4)
	$(CC) $(CFLAGS) -o $(BINSCAN) $(OBJ1) $(OBJ2) $(OBJ3) $(OBJ4) $(FLAGS)

$(OBJ1): libelf64.c
	$(CC) $(CFLAGS) $(FLAGS) -c $< -o $(OBJ1)

$(OBJ2): binscan.c
	$(CC) $(CFLAGS) $(FLAGS) -c $< -o $(OBJ2)

$(OBJ3): openscan.c
	$(CC) $(CFLAGS) $(FLAGS) -c $< -o $(OBJ3)

$(OBJ4): compare.s
	nasm -f elf64 compare.s
clean:
	rm *.o binscan *.bin
