##################################################
## Diplomova  praca                             ##
## Meno studenta: Jozef Vendel                  ##
## Veduci BP: prof. Ing. Milos Drutarovsky CSc. ##
## Skola: KEMT FEI TUKE                         ##
## Datum vytvorenia: 08.09.2021	                ##
##################################################

Zoznam suborov
  
 tcp_salt
     INC
      |__randombytes.h
      |__salt.h
      |__salt_crypto_wrapper.h
      |__salt_io.h
      |__salti_handshake.h
      |__salti_util.h
      |__tweetnacl_modified.h
    SRC_LIB
      |__randombytes.c
      |__salt.c
      |__salt_io.c
      |__salti_handshake.c
      |__salt_io.c
      |__salti_util.c
      |__tweetnacl_modified.c

    __client00.c
    __server00.c
    __readme
    __makefile


Aplikacia vyuziva externu kniznicu TweetNacl pre vykonavanie kryptografickych operacii, pouzivanymi protokolom Salt channelv2 k zabezpeceniu prenasanych dat a ochrane uzivatela. Program demonstruje pouzivanie kryptografickeho protokolu Salt channelv2 k nadviazaniu spojenia medzi klientom a serverom. Ako komunikacny kanal vyuzivam protokol TCP.

Uzivatel skompiluje aplikaciu v prikazovom riadku pomocou nastroja Makefile. Ako prvy sa inicializuje server (volanim: server). Klient, ktory pozna IP adresu servera a cislo portu na ktorom nacuva nove volania, nadviaze komunikaciu (volanim: client 127.0.0.1 8080). Vykona sa TCP Handshake, a v pripade uspechu sa vytvori aj Salt Handshake. Ak vsetko prebehne uspesne, medzi klientom a serverom boli vykonane kryptograficke operacie ako autentizacia oboch stran, dohoda o symetrickom zdielanom kluci, vykonanie hashovania sprav v procese Salt Handshake a pod... (Podrobnejsie sa o tychto kryptografickych operaciach zaoberam v diplomovej praci).
Po tychto procesoch moze klient vymienat zabezpecene data so serverom.  

