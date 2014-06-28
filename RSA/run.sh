#!/bin/sh

rm output*; 

make; ./computeRSA.o; 
./encryptRSA.o sampleFile.txt output.txt; 
./decryptRSA.o output.txt output_.txt
