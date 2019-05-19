CC = g++
OBJ = $(wildcard *.o)
framework = $(wildcard *.framework.o)
tls = $(wildcard *.tls.o)
tst = $(wildcard *.tst.o)
site_src = $(wildcard *.site_src.o)
src = $(wildcard *.src.o)
database = $(wildcard *.database.o)
options = $(wildcard *.options.o)
pybind = $(wildcard *.pybind.o)

EXE = ../https.x ../dndd.x ../middle.x ../site.x ../tls-cl.x ../passafe.x ../test.x ../latex.x ../sql.x
LIBS = -lpthread -lmysqlcppconn -ljsoncpp -lgmpxx -lgmp -lnettle -lstdc++fs 

all : $(EXE) ../catch.x ../tls_crypt.so

../https.x : https.tls.x $(tls) $(framework) $(options)
	$(CC) -o $@ $^ -ljsoncpp -lgmpxx -lgmp -lnettle -lpthread -lstdc++fs

../middle.x : middle.framework.x $(framework) $(options) 
	$(CC) -o $@ $^ -ljsoncpp -lpthread -lstdc++fs

../dndd.x : dndd.src.x $(framework) $(database) $(src) $(options) base64.tls.o
	$(CC) -o $@ $^ -ljsoncpp -lpthread -lstdc++fs -lmysqlcppconn

../site.x : site.site_src.x $(framework) $(database) $(options) $(site_src)
	$(CC) -o $@ $^ -ljsoncpp -lmysqlcppconn -lpthread -lstdc++fs

../tls-cl.x : tls-cl.tls.x $(tls) $(framework) $(options)
	$(CC) -o $@ $^ -ljsoncpp -lgmpxx -lgmp -lnettle -lpthread -lstdc++fs

../catch.x : catch.tx $(tls) $(framework) $(options) $(database) $(tst)
	$(CC) -o $@ $^ $(TOBJ) $(LIBS)

../tls_crypt.so : $(framework) $(tls) $(database) $(pybind) $(options)
	$(CC) -shared -o $@ $^ $(LIBS)

../passafe.x : passavea.tls.x $(framework) $(tls) $(options) 
	$(CC) -o $@ $^ $(LIBS)

../sql.x : mysqlchange.database.x  $(framework) $(tls) $(options) $(database)
	$(CC) -o $@ $^ $(LIBS)

../latex.x : latex.tls.x  $(framework) $(tls) $(options) 
	$(CC) -o $@ $^ $(LIBS)

../test.x : test.tls.x $(framework) $(tls) $(options) 
	$(CC) -o $@ $^ $(LIBS)
	
#    $@ |현재 목표 파일의 이름
#    $* | 확장자를 제외한 현재 목표 파일의 이름
#    $< | 현재 필수 조건 파일 중 첫 번째 파일 이름
#    $? | 현재 대상보다 최슨에 변경된 함수 조건 파일 이름
#    $^ | 현재 모든 필수 조건 파일들

