CFLAG = -g -c -std=c++14 -fmax-errors=1 -pthread -fPIC
INCLUDE = -I../ -I/usr/include/jsoncpp -I/usr/include/python2.7
DIR = $(notdir $(shell pwd))
CC = g++
OBJ = $(patsubst %.cc, ../obj/%.$(DIR).o, $(wildcard *.cc))
MAIN_OBJ = $(patsubst %.cpp, ../obj/%.$(DIR).x, $(wildcard *.cpp))

all : $(OBJ) $(MAIN_OBJ) 

../obj/%.$(DIR).o : %.cc 
	$(CC) $(INCLUDE) $(CFLAG) $< -o $@

../obj/%.$(DIR).x : %.cpp
	$(CC) $(INCLUDE) $(CFLAG) $< -o $@
