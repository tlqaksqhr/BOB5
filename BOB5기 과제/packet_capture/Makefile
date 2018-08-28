CC = g++
CFLAGS = -c -o 
LIBS = -lpcap -Wall -lm -std=c++11

image_capture: main.o image_capture.o
	$(CC) main.o image_capture.o -o image_capture $(LIBS)

main.o : image_capture.h main.cpp
	$(CC) $(CFLAGS) main.o main.cpp $(LIBS)

image_capture.o : image_capture.h image_capture.cpp
	$(CC) $(CFLAGS) image_capture.o image_capture.cpp $(LIBS)

clean:
	rm *.o
