##################################################
## Diplomova praca                              ##
## Meno studenta: Jozef Vendel                  ##
## Veduci DP: prof. Ing. Milos Drutarovsky CSc. ##
## Skola: KEMT FEI TUKE                         ##
## Datum vytvorenia: 28.06.2021	                ##
##################################################

CC=gcc
CFLAGS=-c -O2 -Wall -fcommon -I./INC

#v zavislosti od Windows / Linux
ifeq ($(OS), Windows_NT)
LDFLAGS= -lws2_32 -lm
else
LDFLAGS= -lm
endif

#meno vytvorenej kniznice
LIBRARY=libcrypto.a
#umiestnenie zdrojakov kniznice
SRC_LIB_DIR=SRC_LIB

#automateicke generovanie zdrojakov kniznice
SRC_LIB := $(wildcard $(SRC_LIB_DIR)/*.c)
OBJ_LIB=$(SRC_LIB:.c=.o)

#meno vykonatelneho programu
EXECUTABLE= client server
#vymenovanie zdrojakov aplikacie
SRC_EXE=client00.c server00.c
OBJ_EXE=$(SRC_EXE:.c=.o)


all: $(SRC_EXE) $(SRC_LIB) $(EXECUTABLE)

%: %00.o $(LIBRARY)
	$(CC) -o $@ $+ $(LDFLAGS)

.c.o:
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@


$(LIBRARY): $(OBJ_LIB) #linkovanie suborov kniznice do statickej kniznice
	ar rcu $@ $+
	ranlib $@

clean:
	rm -f $(EXECUTABLE).exe *.o *.a SRC_LIB/*.o

