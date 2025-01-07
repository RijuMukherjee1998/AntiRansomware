nethook.o: %.o: %.c
	clang \
		-target bpf \
		-I/usr/include/$(shell uname -m)-linux-gnu \
		-I/usr/include/linux \
    	-I/usr/include/bcc \
		-g \
		-O2 -c $< -o $@


load:
	bpftool prog load nethook.o /sys/fs/bpf/nhook
	sudo bpftool prog show


clean:
	rm -rf *.o

cleanall:
	bpftool net detach xdp dev wlp114s0
	sudo rm /sys/fs/bpf/nhook
	rm -rf *.o	