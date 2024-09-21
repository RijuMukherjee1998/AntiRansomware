nethook.o: %.o: %.c
	clang \
		-target bpf \
		-I/usr/include/$(shell uname -m)-linux-gnu \
		-g \
		-O2 -c $< -o $@


load:
	bpftool prog load nethook.o /sys/fs/bpf/nhook
	sudo bpftool prog show


clean:
	rm -rf *.o

cleanall:
	bpftool net detach xdp dev eth0
	sudo rm /sys/fs/bpf/nhook
	rm -rf *.o	