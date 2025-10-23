Mod de utilizare a aplicatiei:

1) Pornire server
2) Pornire client/clienti
3) Utilizare comenzi
4) shutdown-server

! Lista tuturor utilizatorilor si a parolelor este in users.conf;
(Format logare: login : <username> <password>)

! Adaugarea a mai multor utilizatori se face tot in users.conf sub forma <username> <password>;

! Este posibila conectarea a mai multor clienți la server;

! Pentru utilizarea comenzii shutdown-server clientul trebuie sa fie logat cu username-ul admin si parola acestuia;

! In cazul in care serverul nu este închis acesta va rula in continuu pana la utilizarea shutdown-server sau a semnalului ctrl+C;

! In cazul in care una din aplicații este oprită prin semnalul ctrl+C este posibil sa rămână filo-urile neșterse, din cauza lipsei cleanup-ului;

! Log-urile serverului (toate comenzile primite de la clienți împreună cu datele acestora) sunt salvate automat in fișierul server.log, fiind actualizat in timp real la fiecare comanda scrisă in client;

! Tema a fost creata pe sistemul de operare macOS. Unele funcții (spre exemplu get-proc-info : <pid>) au fost făcute special pentru sistemul macOS, din cauza neconcordanței cu varianta de rezolvare in sistemul Linux.