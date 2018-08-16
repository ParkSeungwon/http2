CFLAG = -g -c -std=c++17 -fmax-errors=1 -pthread
INCLUDE = -I../ -I../tls/ -I/usr/include/jsoncpp 
CC = g++
TEST_OBJ = $(patsubst %.cc, ../obj/%.t, $(wildcard *.cc))

all : $(TEST_OBJ) ../obj/catch.tx

../obj/%.t : %.cc
	$(CC) $(INCLUDE) $(CFLAG) $< -o $@

../obj/catch.tx : catch.cpp
	$(CC) $(INCLUDE) $(CFLAG) $< -o $@

