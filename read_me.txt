##################################################
## Diplomova  praca                             ##
## Meno studenta: Jozef Vendel                  ##
## Veduci DP: prof. Ing. Milos Drutarovsky CSc. ##
## Skola: KEMT FEI TUKE                         ##
## Datum vytvorenia: 08.09.2021	                ##
##################################################

Zoznam suborov
  
 secure_chat_room_TCP_Salt
      |__INC
      |__SRC_LIB
      |__client00.c
      |__server00.c
      |__readme
      |__makefile
      |__client.bat
      |__server.bat
 
Aplikacia vyuziva externu kniznicu TweetNaCl pre vykonavanie kryptografickych
operacii, pouzivanymi protokolom Salt channelv2 k zabezpeceniu prenasanych 
dat a ochrane uzivatela. Program demonstruje pouzivanie kryptografickeho 
protokolu Salt channelv2 k nadviazaniu zabezpeceneho spojenia medzi 
viacerymi klientami a serverom. Ako komunikacny kanal vyuzivam protokol TCP.

Uzivatel skompiluje aplikaciu v prikazovom riadku pomocou nastroja Makefile. 
Ako prvy sa vola server, kde zadava z prikazoveho riadku svoju 
IP adresu a cislo portu, na ktorom pocuva (volanim: server IPv4 port). 
Klient, ktory pozna IP adresu servera a cislo portu na ktorom nacuva 
nove volania, nadviaze komunikaciu (volanim: client IPv4 port). 
Vykona sa TCP Handshake, a v pripade uspechu sa pristupi k vytvoreniu 
Salt Handshake. Ak vsetko prebehne uspesne, medzi klientom a serverom boli 
vykonane kryptograficke operacie ako autentizacia oboch stran, dohoda o symetrickom
kluci, vykonanie hashovania sprav v procese Salt Handshake a 
pod... (Podrobnejsie sa o tychto kryptografickych operaciach zaoberam v 
diplomovej praci).

Po tychto procesoch moze klient vymienat zabezpecene data s ostatnymi pripojenymi
klientami. Server poskytuje sluzbu chat room, kde kazdy pripojeni klient k serveru 
moze odosielat a prijimat data od ostatnych pripojenych uzivateloch.  

Zdrojove kody su prenositelne medzi operacnymi systemami Linux a Windows 
bez ziadnej upravy s pouzitim makefile suboru.
