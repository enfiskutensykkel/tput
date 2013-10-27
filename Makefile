CC=$(if $(shell which colorgcc),colorgcc,gcc)
LD=gcc
CFLAGS=-O3 -Wall -Wextra -pedantic

SRC=tput.c
OBJ=$(SRC:%.c=%.o)

.PHONY: tput all clean

tput: $(OBJ)
	$(LD) -o $@ $^ -lpcap

all: tput

clean:
	-$(RM) $(OBJ) tput

%.o: %.c
	$(CC) -std=gnu99 -DDEFAULT_TIME_SLICE=30 -o $@ -c $(CFLAGS) $<
