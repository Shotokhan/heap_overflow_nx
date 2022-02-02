# heap_overflow_nx

This project is to practice heap overflow on a function pointer, with NX heap & stack; then, you need to perform a multi-stage exploit to get a shell. <br>
What you find in this repository:

- in ```/docs``` directory you find documentation in PDF, written in Italian, and some video traces of the exploit (for local and remote execution, which are slightly different);
- in ```/old``` directory you find the first experiments related to this project, including the source code and the executable with a win function, which may be useful if you want to reliably test the first stage of the exploit;
- in ```/program``` directory you find the dockerized challenge itself;
- ```heappy_patchelf``` is the compiled program, patched using [patchelf](https://github.com/NixOS/patchelf) to use ```libc-2.19.so``` and ```ld-2.19.so``` on any Linux system, which are the libraries used within the docker image;
- ```trace_exploit.py``` is a modified version of ```exploit.py``` to trace I/O with the local or remote process during exploitation;
- ```note_heappy.txt``` are some notes, in Italian, taken during the development of the lab.

