# Pollux

Pollux is a simple program written in C that finds duplicate files. It is named after one of the twin stars in the
constellation Gemini (literally, "twins"), its twin being Castor.

Pollux scans directories recursively and creates a binary tree of filenames and their hash digests. When a duplicate file
is encountered, Pollux will see that there is already a node in the tree with the same digest.

Several options can be specified:

-s, --start       specify the starting directory (default is the current working directory).
--blacklist       use to specify keywords of directories in which you do not wish to descend.
-H, --hash        specify the hash digest to use (the default is sha256).
-N, --nodelete    don't delete the duplicate files (useful for testing).
-o, --out         specify the output file to view the output from the scan (default is "removed_duplicates_${TIMESTAMP}.txt", where
                         ${TIMESTAMP} is the number of seconds since the Epoch).
-h, --help        display this information.
