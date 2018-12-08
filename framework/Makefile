CFLAG = -g -c -std=c++17 -fmax-errors=1 -pthread -fPIC
INCLUDE = -I../ -I../src/ -I../database/ -I/usr/include/p11-kit-1
DIR = $(notdir $(shell pwd))
CC = g++
OBJ = $(patsubst %.cc, ../obj/%.$(DIR).o, $(wildcard *.cc))
MAIN_OBJ = $(patsubst %.cpp, ../obj/%.$(DIR).x, $(wildcard *.cpp))

all : $(MAIN_OBJ) $(OBJ)

../obj/%.$(DIR).o : %.cc 
	$(CC) $(INCLUDE) $(CFLAG) $< -o $@

../obj/%.$(DIR).x : %.cpp
	$(CC) $(INCLUDE) $(CFLAG) $< -o $@
