all:
	gcc -pthread tcp_traceroute.c -o traceroute 

clean:
	rm traceroute