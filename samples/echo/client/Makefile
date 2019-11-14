
.PHONY:
all:
	rm -rf client 
	gcc -o client	\
		-fpermissive	\
		-D_DEBUG	\
		-I../../../ -I.	\
		client.cpp	\
		-lrt -pthread -lstdc++	\
		-L../../../	-lXSocket
   			   


