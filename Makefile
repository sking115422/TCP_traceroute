all:
	gcc tcp_traceroute.c -o traceroute 

clean:
	rm traceroute