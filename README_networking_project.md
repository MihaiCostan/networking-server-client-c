# 🖧 FIFO-Based Client–Server Communication System (C, POSIX IPC)

Acest proiect implementează un sistem complet de comunicare **client–server** în limbajul **C**, utilizând **FIFO-uri (named pipes)**, **procese multiple** și un **monitor separat** pentru logarea comenzilor. Serverul gestionează autentificarea utilizatorilor, execuția comenzilor și comunicarea cu mai mulți clienți simultan.

---

## ⚙️ Caracteristici principale

- **Comunicare bidirecțională** între server și unul sau mai mulți clienți (FIFO)
- **Autentificare pe bază de fișier `users.conf`**
- **Monitor separat** (proces copil) care scrie loguri detaliate pentru fiecare comandă primită
- **Gestionează până la `MAX_CLIENTS = 32` sesiuni simultane**
- **Protecție împotriva dublului login**
- **Comenzi administrative**, inclusiv închiderea controlată a serverului
- **Comenzi de sistem**: listare utilizatori activi, informații despre procese, etc.

---

## 🧠 Arhitectură

```
+-------------------+             +-------------------+
|     CLIENT 1      |             |     CLIENT N      |
|  stdin/stdout UI  |             |  stdin/stdout UI  |
|  client_PID_fifo  |             |  client_PID_fifo  |
+-------------------+             +-------------------+
          \                             /
           \                           /
            \                         /
           +---------------------------+
           |         SERVER            |
           | - Ascultă comenzi prin    |
           |   server_fifo             |
           | - Fork() pe comandă       |
           | - Gestionează sesiuni     |
           | - Trimite răspunsuri      |
           +-------------+-------------+
                         |
                         |
                +------------------+
                |   MONITOR PROC   |
                | - primește mesaje |
                |   prin socketpair |
                | - scrie în loguri |
                +------------------+
```

---

## 🚀 Cum se rulează

### 1️⃣ Compilare
```zsh
gcc server.c -o server
gcc client.c -o client
```

### 2️⃣ Pornirea serverului
```zsh
./server
```

### 3️⃣ Pornirea unuia sau mai multor clienți
```zsh
./client
```

### 4️⃣ Comenzi disponibile
| Comandă | Descriere |
|----------|------------|
| `login : <username> <password>` | Autentificare utilizator |
| `get-logged-users` | Listează utilizatorii activi pe sistem |
| `get-proc-info : <pid>` | Afișează informații despre un proces (PID, memorie, user) |
| `logout` | Deconectează utilizatorul curent |
| `quit` | Închide aplicația client |
| `shutdown-server` | Închide serverul *(doar pentru admin)* |

---

## 🧾 Fișiere

| Fișier | Rol |
|--------|-----|
| `server.c` | Serverul principal care gestionează FIFO-urile, sesiunile și procesele |
| `client.c` | Interfața pentru utilizator — trimite comenzi și afișează răspunsurile |
| `users.conf` | Fișier text cu perechi `<username> <password>` |
| `server.log` | Logul central al serverului (monitorizat în timp real) |
| `Makefile` | Script de compilare (opțional) |

---

## 🔐 Securitate & restricții
- Numai utilizatorul `admin` poate executa comanda `shutdown-server`.
- Fiecare utilizator poate fi logat o singură dată simultan.
- FIFO-urile sunt curățate la închidere (`unlink()`).
- Monitorul rulează într-un proces separat și înregistrează toate evenimentele cu timestamp.

---

## ⚠️ Observații
- Proiectul este dezvoltat pe **macOS**, iar unele funcții (precum `get-proc-info`) folosesc **API-ul `libproc`**, specific acestui sistem.
- Poate necesita mici modificări pentru rulare pe Linux (înlocuirea `proc_pidinfo` cu `/proc` API).

---

## 🪄 Posibile îmbunătățiri
- Portare completă pentru Linux  
- Implementarea unui protocol TCP în loc de FIFO-uri  
- Adăugarea criptării TLS între client și server  
- Mecanism de **cleanup automat** la semnale (`SIGINT`, `SIGTERM`)  
- Persistența sesiunilor în fișiere sau baze de date

---

## 🧑‍💻 Autor
Proiect realizat în limbajul **C**, cu accent pe:
- comunicare inter-proces (IPC)
- programare concurentă
- logging avansat

Dezvoltat în cadrul **Facultății de Informatică Iași (UAIC)**, pentru aprofundarea conceptelor de **sisteme de operare** și **networking**.
