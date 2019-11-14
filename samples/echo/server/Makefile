
.PHONY:
all:
	rm -rf server 
	gcc -o server	\
		-fpermissive	\
		-D_DEBUG	\
		-I../../../ -I.	\
		server.cpp	\
		-lrt -pthread -lstdc++	\
		-L../../../	-lXSocket
   			   


