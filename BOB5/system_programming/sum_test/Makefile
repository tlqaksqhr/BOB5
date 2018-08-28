all: sum_test

sum_test: main.o sum.o
	g++ -g -o sum_test main.o sum.o

sum.o: sum.h sum.cpp
	g++ -g -c -o sum.o sum.cpp

main.o: main.cpp
	g++ -g -c -o main.o main.cpp

clean:
	rm -f *.o sum_test
