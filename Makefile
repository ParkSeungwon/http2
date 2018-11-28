all : 
	incltouch.x
	make -C src/
	make -C framework/
	make -C database/
	make -C tls/
	make -C options/
	make -C site_src/
	make -C tst/
	make -C obj/
	./catch.x

clean :
	rm obj/*.? *.x

