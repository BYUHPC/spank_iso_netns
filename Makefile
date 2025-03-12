CC := gcc

all:
	$(CC) -I/usr/local/src/slurm -fPIC -shared -lcap -o spank_iso_netns.so spank_iso_netns.c

install: all
	@echo "You need to manually copy the spank_iso_netns.so file to the destination directory"
	@exit 1
