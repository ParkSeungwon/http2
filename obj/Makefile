CC = g++
OBJ = $(wildcard *.o)
TOBJ = $(wildcard *.t)
EXE = $(patsubst %.x, ../%.x, $(wildcard *.x))
gtkmmLIB = $(shell pkg-config gtkmm-3.0 --libs)
LIBS = -lpthread -lmysqlcppconn -ljsoncpp -lgmpxx -lgmp -lwolfssl -lstdc++fs -lfmt

all : $(EXE) ../catch.x

../%.x : %.x $(OBJ)
	$(CC) -o $@ $< $(OBJ) $(LIBS)

../catch.x : catch.tx $(OBJ) $(TOBJ)
	$(CC) -o $@ $< $(OBJ) $(TOBJ) $(LIBS)
