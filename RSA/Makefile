@all:
	@echo "[STATUS] - building computeModular.c to computeModular.o ..."
	cc computeModular.c -o computeModular.o -lssl -lcrypto -Wno-deprecated -Wno-deprecated-declarations -Wno-implicit-function-declaration
	@echo "[STATUS] - building computeRSA.c to computeRSA.o ..."
	cc computeRSA.c -o computeRSA.o -lssl -lcrypto -Wno-deprecated -Wno-deprecated-declarations -Wno-implicit-function-declaration
	@echo "\n[DONE] - Done ...\n"
clean:
	rm *.o
