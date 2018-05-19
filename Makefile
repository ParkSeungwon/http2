all : 
	make -C src/
	make -C framework/
	make -C database/
	make -C tls/
	make -C tst/
	make -C obj/
	./catch.x

clean :
	rm obj/*.? *.x

