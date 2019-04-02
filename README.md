# Pollux

Pollux is a simple program written in C that finds duplicate files. It is named after one of the twin stars in the constellation Gemini (literally, "twins"), its twin being Castor.

Pollux scans directories recursively and creates a binary tree of filenames and their sizes. When files are encountered with the
exact same size, Pollux calculates their respective SHA-256 message digests and compares them. If they are the same, the files
are duplicate files; otherwise, an array pointed to by the node in the tree is created, where all same-sized files are kept,
along with their message digests for quick comparison.

If you want to test some sort of optimisation, first copy pollux.c to pollux0.c. Make the changes in pollux0.c, and compile as
pollux0 (gcc -Wall -Werror -o pollux0 pollux.c -lcrypto). Then run the script ./speed_test. The script creates 10 folders in
./TESTING (0 - 9). Test files are created: one third are identical to one another; the rest contain a random number. Since the
files containing random numbers tend to be the same size as one another (4 - 6 bytes), this is a good bottleneck test since it
results in a high number of comparisons with those stored in the array. First, 10000 such files are created, and this number doubles after each iteration (for a total of 4 iterations).
