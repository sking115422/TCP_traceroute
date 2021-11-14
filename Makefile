all:
	gcc -pthread tcp_traceroute.c -o traceroute 

clean:
	rm traceroute
	rm test
	sudo rm -r bin_files