CFLAG = -g -c -std=c++17 -fmax-errors=1 -pthread
INCLUDE = -I../ -I../tls/ -I/usr/include/jsoncpp -I/usr/include/crypto++
CC = g++
DIR = $(notdir $(shell pwd))
TEST_OBJ = $(patsubst %.cc, ../obj/%.$(DIR).o, $(wildcard *.cc))

all : $(TEST_OBJ) ../obj/catch.tx

../obj/%.$(DIR).o : %.cc
	$(CC) $(INCLUDE) $(CFLAG) $< -o $@

../obj/catch.tx : catch.cpp
	$(CC) $(INCLUDE) $(CFLAG) $< -o $@

