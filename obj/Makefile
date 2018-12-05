CC = g++
OBJ = $(wildcard *.o)
OOBJ = $(wildcard *.O)
TOBJ = $(wildcard *.t)
EXE = $(patsubst %.x, ../%.x, $(wildcard *.x))
gtkmmLIB = $(shell pkg-config gtkmm-3.0 --libs)
LIBS = -lpthread -lmysqlcppconn -ljsoncpp -lgmpxx -lgmp -lwolfssl -lstdc++fs 

all : $(EXE) ../catch.x ../tls_crypt.so

../%.x : %.x $(OBJ)
	$(CC) -o $@ $< $(OBJ) $(LIBS)

../catch.x : catch.tx $(OBJ) $(TOBJ)
	$(CC) -o $@ $< $(OBJ) $(TOBJ) $(LIBS)

../tls_crypt.so : $(OOBJ)
	$(CC) -shared -o $@ $(OOBJ) $(LIBS)
