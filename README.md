# Pollux

Pollux is a simple program written in C that finds duplicate files. It is named after one of the twin stars in the constellation Gemini (literally, "twins"), its twin being Castor.

Pollux scans directories recursively and creates a binary tree of filenames and their hash digests. When a duplicate file is encountered, Pollux will see that there is already a node in the tree with the same digest. For testing purposes, an option can be specified so that duplicate files will be listed but not deleted. Run "./pollux -h" to see information on various options.

USES CUSTOM DYNAMIC SHARED LIBRARIES!

Do the following (linux-based kernels) to set them up:

```
gcc -c -Wall -Werror -fPIC nameoflib.c
gcc -shared -o libnameoflib.so nameoflib.o
sudo cp libnameoflib.so /usr/lib/libnameoflib.so
sudo chmod 755 /usr/lib/libnameoflib.so
sudo ldconfig
```
