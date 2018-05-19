CC = g++
OBJ = $(wildcard *.o)
TOBJ = $(wildcard *.t)
EXE = $(patsubst %.x, ../%.x, $(wildcard *.x))
gtkmmLIB = $(shell pkg-config gtkmm-3.0 --libs)

all : $(EXE) ../catch.x

../%.x : %.x $(OBJ)
	$(CC) -o $@ $< $(OBJ) -lpthread -lmysqlcppconn -ljsoncpp -lgmpxx -lgmp -lwolfssl

../catch.x : catch.tx $(OBJ) $(TOBJ)
	$(CC) -o $@ $< $(OBJ) $(TOBJ) -lpthread -lmysqlcppconn -ljsoncpp -lgmpxx -lgmp -lwolfssl
