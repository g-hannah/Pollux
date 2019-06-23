# Pollux

Pollux is a simple program written in C that finds duplicate files. It is named after one of the twin stars in the constellation Gemini (literally, "twins"), its twin being Castor.

Pollux scans directories recursively and creates a binary tree of filenames and their sizes. When files are encountered with the
exact same size, Pollux calculates their respective SHA-256 message digests and compares them. If they are the same, the files
are duplicate files; otherwise, an array pointed to by the node in the tree is created, where all same-sized files are kept,
along with their message digests for quick comparison.
