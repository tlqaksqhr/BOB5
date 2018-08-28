CC = g++
CFLAGS = -c -o 
LIBS = -lnetfilter_queue -std=c++11

mal_site: mal_site.o
		$(CC) mal_site.o -o mal_site $(LIBS)

mal_site.o : mal_site.cpp
		$(CC) $(CFLAGS) mal_site.o mal_site.cpp $(LIBS)
clean:
		rm *.o
