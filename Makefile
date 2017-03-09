CC=$(if $(shell which colorgcc),colorgcc,gcc)
LD=gcc
CFLAGS=-O3 -Wall -Wextra -pedantic

HDR=src/stream.h src/filter.h
SRC=src/main.cpp src/stream.cpp src/filter.cpp
OBJ=$(SRC:src/%.cpp=build/%.o)

.PHONY: tput all clean

tput: $(OBJ)
	$(LD) -o $@ $^ -lstdc++ -lpcap

all: tput

clean:
	-$(RM) $(OBJ) tput

build/%.o: src/%.cpp
	@mkdir -p build
	$(CC) -std=gnu++11 -DDEFAULT_TIME_SLICE=100 -DETHERNET_FRAME_LEN=14 -o $@ -c $(CFLAGS) $<
