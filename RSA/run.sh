#!/bin/sh

make clean;
make;
./computeRSA.o;
./encryptRSA.o sampleFile.txt output.txt;
./decryptRSA.o output.txt output_.txt;


