CC=$(if $(shell which colorgcc),colorgcc,gcc)
LD=gcc
CFLAGS=-O3 -Wall -Wextra -pedantic

SRC=main.cpp stream.cpp filter.cpp
OBJ=$(SRC:%.cpp=%.o)

.PHONY: tput all clean

tput: $(OBJ)
	$(LD) -o $@ $^ -lstdc++ -lpcap

all: tput

clean:
	-$(RM) $(OBJ) tput

%.o: %.cpp
	$(CC) -std=gnu++98 -DDEFAULT_TIME_SLICE=30000 -DETHERNET_FRAME_LEN=14 -o $@ -c $(CFLAGS) $<
