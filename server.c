#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <utmpx.h>
#include <libproc.h>
#include <pwd.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>

#define SERVER_FIFO_PATH "server_fifo"
#define CLIENT_FIFO_PATH "client_%d_fifo"
#define CONFIG_FILE "users.conf"
#define BUF_SIZE 1024
#define MAX_CLIENTS 32

int shutdown_server = 0;
int monitor_fd = -1;

typedef struct
{
    pid_t pid;
    char username[64];
    int logged_in;
} ClientSession;
ClientSession sessions[MAX_CLIENTS];

ClientSession *get_or_create_session(pid_t client_pid)
{
    // cauta sesiune existenta
    for (int i = 0; i < MAX_CLIENTS; i++)
    {
        if (sessions[i].pid == client_pid)
            return &sessions[i];
    }
    // daca nu exista, creeaza una noua
    for (int i = 0; i < MAX_CLIENTS; i++)
    {
        if (sessions[i].pid == 0)
        {
            sessions[i].pid = client_pid;
            sessions[i].logged_in = 0;
            sessions[i].username[0] = '\0';
            return &sessions[i];
        }
    }

    // in cazul in care nu am gasit o sesiune a pid-ului actual al clientului SI s a atins MAX_CLIENTS
    return NULL;
}

void run_monitor_process(int sock_fd, pid_t server_pid)
{
    FILE *log = fopen("server.log", "a");
    if (!log)
    {
        perror("[MONITOR] Eroare la deschiderea logului!\n");
        _exit(1);
    }

    fprintf(log, "[MONITOR PID=%d]: Procesul de monitorizare a comenzilor pornit pentru serverul cu PID=%d\n", getpid(), server_pid);
    fflush(log);

    char msg[512];
    while (1)
    {
        ssize_t r = read(sock_fd, msg, sizeof(msg) - 1);
        if (r <= 0)
            break;

        msg[r] = '\0';
        // scriem eventul in fisier
        time_t now = time(NULL);
        char timestr[64];
        strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S", localtime(&now));
        fprintf(log, "[%s] %s\n", timestr, msg);
        fflush(log);

        // daca serverul trimite SHUTDOWN, inchidem monitorul
        if (strstr(msg, "shutdown-server") && !strstr(msg, "FAILED: \"shutdown-server"))
        {
            fprintf(log, "[MONITOR PID=%d] Primit SHUTDOWN. Inchid monitorul.\n\n", getpid());
            fflush(log);
            break;
        }
    }

    fclose(log);
    close(sock_fd);
    _exit(0);
}

int login_username(const char *user, const char *pass, char *raspuns, size_t size_raspuns)
{
    FILE *file = fopen(CONFIG_FILE, "r");
    if (file == NULL)
    {
        fprintf(stderr, "[SERVER]: Eroare la deschiderea fisierului users.conf!\n");
        _exit(0);
    }

    char line[256], username[128], password[128];
    while (fgets(line, sizeof(line), file))
    {
        line[strcspn(line, "\n")] = '\0';
        if (sscanf(line, "%127s %127s", username, password) == 2)
        {
            if (strcmp(username, user) == 0 && strcmp(password, pass) == 0)
            {
                fclose(file);
                return 1;
            }
        }
    }
    fclose(file);
    return 0;
}

int este_username_deja_logat(const char *username)
{
    for (int i = 0; i < MAX_CLIENTS; i++)
    {
        if (sessions[i].logged_in && strcmp(sessions[i].username, username) == 0)
        {
            return 1; // username-ul e deja logat
        }
    }
    return 0; // liber
}

void get_logged_users(char *raspuns, size_t size_raspuns)
{
    struct utmpx *entry;
    setutxent();

    ssize_t len = 0;
    while ((entry = getutxent()) != NULL)
    {
        if (entry->ut_user[0] != '\0')
        {
            char timebuf[64];
            time_t t = entry->ut_tv.tv_sec;
            struct tm *tm_info = localtime(&t);
            strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", tm_info);
            len += snprintf(raspuns + len, size_raspuns - len, "User: %s\tHost: %s\tLogin Time: %s\n", entry->ut_user, entry->ut_host, timebuf);
            if (len >= size_raspuns)
                break;
        }
    }
    endutxent();
}

void get_proc_info(pid_t pid, char *raspuns, size_t size_raspuns)
{
    struct proc_bsdinfo bsdinfo;   // pentru name, state (nu pot face rost de el pe macOS), ppid, uid
    struct proc_taskinfo taskinfo; // pentru vsize, resident size

    int ret1 = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &bsdinfo, sizeof(bsdinfo));
    int ret2 = proc_pidinfo(pid, PROC_PIDTASKINFO, 0, &taskinfo, sizeof(taskinfo));

    if (ret1 <= 0)
    {
        snprintf(raspuns, size_raspuns, "Nu am putut obtine info pentru PID %d\n", pid);
        return;
    }

    struct passwd *pw = getpwuid(bsdinfo.pbi_uid); // obtin numele utilizatorului din UID
    const char *username = pw ? pw->pw_name : "unknown";

    snprintf(raspuns, size_raspuns,
             "Name: %s\n"
             "State:  N/A (macOS doesn't expose process state)\n"
             "PPid: %d\n"
             "Uid: %d (%s)\n"
             "VSize: %llu KB\n"
             "Resident Size: %llu KB\n",
             bsdinfo.pbi_name,
             bsdinfo.pbi_ppid,
             bsdinfo.pbi_uid,
             username,
             taskinfo.pti_virtual_size / 1024,
             taskinfo.pti_resident_size / 1024);
}

void executa_comanda_in_copil(const char *cmd, int out_fd, ClientSession *session)
{
    char raspuns[4096] = "";
    // curat bufferul de raspuns
    memset(raspuns, 0, sizeof(raspuns));

    // login
    if (strncmp("login :", cmd, 7) == 0)
    {
        char user[64], pass[64];
        if (sscanf(cmd + 7, "%63s %63s", user, pass) != 2)
        {
            snprintf(raspuns, sizeof(raspuns), "Format invalid! Foloseste: login : <username> <parola>\n");
            if (monitor_fd != -1)
            {
                char event[256];
                snprintf(event, sizeof(event), "--> FAILED! \"login (format_invalid   client_pid: %d)\"", session->pid);
                write(monitor_fd, event, strlen(event));
            }
        }
        else if (session->logged_in == 1)
        {
            snprintf(raspuns, sizeof(raspuns), "Eroare! Esti deja logat cu username-ul %s!\n", session->username);
            if (monitor_fd != -1)
            {
                char event[256];
                snprintf(event, sizeof(event), "--> FAILED! \"login (already_logged_username: %s   client_pid: %d)\"", session->username, session->pid);
                write(monitor_fd, event, strlen(event));
            }
        }
        else
        {
            if (login_username(user, pass, raspuns, sizeof(raspuns)))
            {
                if (este_username_deja_logat(user) == 1)
                {
                    snprintf(raspuns, sizeof(raspuns), "LOGIN_FAILED! Utilizatorul %s este deja logat pe alt client!\n", user);
                    if (monitor_fd != -1)
                    {
                        char event[256];
                        snprintf(event, sizeof(event), "--> FAILED! \"login (username_already_logged_elsewhere: %s   client_pid: %d)\"", user, session->pid);
                        write(monitor_fd, event, strlen(event));
                    }
                }
                else
                {
                    snprintf(raspuns, sizeof(raspuns), "LOGIN_SUCCES! Ai fost logat cu username-ul %s!\n", user);
                    if (monitor_fd != -1)
                    {
                        char event[256];
                        snprintf(event, sizeof(event), "--> login (username: %s   client_pid: %d)", user, session->pid);
                        write(monitor_fd, event, strlen(event));
                    }
                }
            }
            else
            {
                snprintf(raspuns, sizeof(raspuns), "LOGIN_FAILED! Username sau parola gresita pentru utilizatorul: %s!\n", user);
                if (monitor_fd != -1)
                {
                    char event[256];
                    snprintf(event, sizeof(event), "--> FAILED! \"login (wrong_username_or_password: %s   client_pid: %d)\"", user, session->pid);
                    write(monitor_fd, event, strlen(event));
                }
            }
        }
    }

    // get-logged-users
    else if (strcmp("get-logged-users", cmd) == 0)
    {
        if (!session->logged_in)
        {
            snprintf(raspuns, sizeof(raspuns), "Eroare! Trebuie sa fii logat pentru a utiliza acesata comanda: %s!\n", cmd);
            if (monitor_fd != -1)
            {
                char event[256];
                snprintf(event, sizeof(event), "--> FAILED! \"get-logged-users (username: %s   unlogged_client_pid: %d)\"", session->username, session->pid);
                write(monitor_fd, event, strlen(event));
            }
        }
        else
        {
            get_logged_users(raspuns, sizeof(raspuns));
            if (monitor_fd != -1)
            {
                char event[256];
                snprintf(event, sizeof(event), "--> get-logged-users (username: %s   client_pid: %d)", session->username, session->pid);
                write(monitor_fd, event, strlen(event));
            }
        }
    }

    // get-proc-info
    else if (strncmp("get-proc-info :", cmd, 15) == 0)
    {
        pid_t pid_de_procesat = 0;
        sscanf(cmd + 15, "%d", &pid_de_procesat);
        if (!session->logged_in)
        {
            snprintf(raspuns, sizeof(raspuns), "Eroare! Trebuie sa fii logat pentru a utiliza acesata comanda: %s!\n", cmd);
            if (monitor_fd != -1)
            {
                char event[256];
                snprintf(event, sizeof(event), "--> FAILED! \"get-proc-info (username: %s   unlogged_client_pid: %d   target_pid: %d)\"", session->username, session->pid, pid_de_procesat);
                write(monitor_fd, event, strlen(event));
            }
        }
        else
        {
            get_proc_info(pid_de_procesat, raspuns, sizeof(raspuns));
            if (monitor_fd != -1)
            {
                char event[256];
                snprintf(event, sizeof(event), "--> get-proc-info (username: %s   client_pid: %d   target_pid: %d)\"", session->username, session->pid, pid_de_procesat);
                write(monitor_fd, event, strlen(event));
            }
        }
    }

    // logout
    else if (strcmp("logout", cmd) == 0)
    {
        if (!session->logged_in)
        {
            snprintf(raspuns, sizeof(raspuns), "Eroare! Trebuie sa fii logat pentru a utiliza acesata comanda: %s!\n", cmd);
            if (monitor_fd != -1)
            {
                char event[256];
                snprintf(event, sizeof(event), "--> FAILED! \"logout (username: %s   unlogged_client_pid: %d)\"", session->username, session->pid);
                write(monitor_fd, event, strlen(event));
            }
        }
        else
        {
            snprintf(raspuns, sizeof(raspuns), "LOGOUT_SUCCES! Ai fost delogat cu username-ul %s!\n", session->username);
            if (monitor_fd != -1)
            {
                char event[256];
                snprintf(event, sizeof(event), "--> logout (username: %s   client_pid: %d)", session->username, session->pid);
                write(monitor_fd, event, strlen(event));
            }
        }
    }

    // shutdown
    else if (strcmp("shutdown-server", cmd) == 0)
    {
        if (session->logged_in && strcmp(session->username, "admin") == 0)
        {
            snprintf(raspuns, sizeof(raspuns), "SHUTDOWN_SERVER! Comanda primita de la admin, serverul s-a inchis!\n");
            if (monitor_fd != -1)
            {
                char event[256];
                snprintf(event, sizeof(event), "--> shutdown-server (username: %s   client_pid: %d)", session->username, session->pid);
                write(monitor_fd, event, strlen(event));
            }
        }
        else
        {
            snprintf(raspuns, sizeof(raspuns), "Eroare! Trebuie sa fii logat ca admin pentru a putea utiliza aceasta comanda: %s!\n", cmd);
            if (monitor_fd != -1)
            {
                char event[256];
                snprintf(event, sizeof(event), "--> FAILED: \"shutdown-server (username: %s   client_pid: %d)\"", session->username, session->pid);
                write(monitor_fd, event, strlen(event));
            }
        }
    }

    // quit
    else if (strncmp(cmd, "quit", 4) == 0)
    {
        snprintf(raspuns, sizeof(raspuns), "CLIENT QUIT! Goodbye!\n");
        if (monitor_fd != -1)
        {
            char event[256];
            snprintf(event, sizeof(event), "--> quit (client_pid: %d)", session->pid);
            write(monitor_fd, event, strlen(event));
        }
    }
    else
    {
        snprintf(raspuns, sizeof(raspuns), "Eroare! Comanda folosita este necunoscuta: %s!\n", cmd);
        if (monitor_fd != -1)
        {
            char event[256];
            snprintf(event, sizeof(event), "--> UNKNOWN_COMMAND: \"%s\" (username: %s;   client_pid: %d)", cmd, session->username, session->pid);
            write(monitor_fd, event, strlen(event));
        }
    }
    write(out_fd, raspuns, strlen(raspuns));
    _exit(0);
}

int trimite_raspuns_la_client(pid_t client_pid, const char *buf)
{
    char fifo_client[128];
    snprintf(fifo_client, sizeof(fifo_client), CLIENT_FIFO_PATH, client_pid);

    int fd_write = open(fifo_client, O_WRONLY);
    if (fd_write == -1)
    {
        fprintf(stderr, "[SERVER] Eroare la open client fifo %s: %s\n", fifo_client, strerror(errno));
        return -1;
    }
    //!!!
    uint32_t lungime = strlen(buf);
    uint32_t lungime_network = htonl(lungime); // conversie la big-endian (retea)

    // lungimea raspunsului
    if (write(fd_write, &lungime_network, sizeof(lungime_network)) != sizeof(lungime_network))
    {
        fprintf(stderr, "[SERVER] Eroare la trimiterea lungimii raspunsului\n");
        close(fd_write);
        return -1;
    }

    // raspunsul
    if (write(fd_write, buf, lungime) != (ssize_t)lungime)
    {
        fprintf(stderr, "[SERVER] Eroare la trimiterea continutului raspunsului\n");
        close(fd_write);
        return -1;
    }
    close(fd_write);
    return 1;
}

int main()
{
    pid_t server_pid = getpid();

    for (int i = 0; i < MAX_CLIENTS; i++)
    {
        sessions[i].pid = 0;
        sessions[i].logged_in = 0;
    }

    // server_fifo
    if (mkfifo(SERVER_FIFO_PATH, 0666) == -1 && errno != EEXIST)
    {
        fprintf(stderr, "[SERVER]: mkfifo SERVER_FIFO!\n");
        exit(EXIT_FAILURE);
    }
    int fifo_server = open(SERVER_FIFO_PATH, O_RDONLY | O_NONBLOCK);
    if (fifo_server == -1)
    {
        fprintf(stderr, "[SERVER] Eroare la open SERVER_FIFO_PATH\n");
        exit(EXIT_FAILURE);
    }
    printf("\n[SERVER]: Serverul cu SERVER_PID:%d Pornit.\n", server_pid);

    // socket cu proces separat pt monitorizarea comenzilor utilizate/incercate
    int monitor_socket[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, monitor_socket) == -1)
    {
        fprintf(stderr, "[SERVER]: Eroare la socketpair()!\n");
        exit(EXIT_FAILURE);
    }
    pid_t monitor_pid = fork();
    if (monitor_pid == -1)
    {
        fprintf(stderr, "[SERVER]: Eroare la monitor_fork()!\n");
        exit(EXIT_FAILURE);
    }
    if (monitor_pid == 0)
    {
        close(monitor_socket[0]); // inchide capatul serverului
        run_monitor_process(monitor_socket[1], server_pid);
        _exit(0);
    }
    else
    {
        close(monitor_socket[1]); //inchid capatul monitorului
        monitor_fd = monitor_socket[0];

        while (!shutdown_server)
        {
            // preiau datele din fifo_server (comenzile trimise de la client)
            char buf[BUF_SIZE];
            ssize_t bytes = read(fifo_server, buf, sizeof(buf) - 1);
            if (bytes == -1 && errno == EAGAIN)
            {
                usleep(1000);
                continue;
            }
            else if (bytes == 0)
            {
                continue;
            }
            buf[bytes] = '\0';

            // separ formatul: client_pid;command
            pid_t client_pid;
            char command[BUF_SIZE];
            sscanf(buf, "%d;%1023[^\n]", &client_pid, command);
            // printf("[SERVER]: Cerere de la CLIENT_PID=%d: '%s'\n", client_pid, command); // inlocuita cu monitorizarea

            // caut sau creez o sesiune pt client
            ClientSession *session = get_or_create_session(client_pid);
            if (!session)
            {
                fprintf(stderr, "[SERVER]: SESIONS FULL! Nu pot crea sesiune nouă pentru PID=%d\n", client_pid);
                continue;
            }

            int pipe_fd[2];
            if (pipe(pipe_fd) == -1)
            {
                fprintf(stderr, "[SERVER]: Eroare la pipe()!\n");
                continue;
            }

            pid_t pid = fork();
            if (pid < 0)
            {
                fprintf(stderr, "[SERVER]: Eroare la fork()!\n");
                close(pipe_fd[0]);
                close(pipe_fd[1]);
                continue;
            }
            if (pid == 0) // proces copil
            {
                close(pipe_fd[0]); // inchid capat citire
                executa_comanda_in_copil(command, pipe_fd[1], session);
                close(pipe_fd[1]);
                _exit(0);
            }
            else // proces parinte
            {
                close(pipe_fd[1]); // inchid capat scriere
                char raspuns[BUF_SIZE];
                // curat bufferul de raspuns
                memset(raspuns, 0, sizeof(raspuns));
                ssize_t r = read(pipe_fd[0], raspuns, sizeof(raspuns) - 1);
                if (r > 0)
                {
                    // scrise in procesul parinte deoarece daca le scriam in copil, memoria procesului este copiată (copy-on-write) iar datele variabilelor nu persistau si in procesul parinte
                    if (trimite_raspuns_la_client(client_pid, raspuns) == -1)
                    {
                        fprintf(stderr, "[SERVER]: Eroare la trimiterea raspunsului catre CLIENT_PID=%d\n", client_pid);
                    }
                    if (strncmp(raspuns, "LOGIN_SUCCES!", 13) == 0)
                    {
                        char user[64];
                        sscanf(raspuns + 43, "%63[^!]", user);
                        raspuns[r] = '\0';
                        session->logged_in = 1;
                        strcpy(session->username, user);
                    }
                    else if (strncmp(raspuns, "LOGOUT_SUCCES!", 14) == 0)
                    {
                        session->logged_in = 0;
                        session->username[0] = '\0';
                    }
                    else if (strncmp(raspuns, "SHUTDOWN_SERVER", 15) == 0)
                    {
                        shutdown_server = 1;
                        printf("[SERVER]: Comanda de închidere primită. Se oprește SERVER_PID:%d...\n", server_pid);
                        break;
                    }
                }
                else
                {
                    fprintf(stderr, "[SERVER]: Eroare/Nu am primit raspuns de la copil!\n");
                }
                close(pipe_fd[0]);
                waitpid(pid, NULL, 0);
            }
        }
    }
    close(fifo_server);
    unlink(SERVER_FIFO_PATH);
    return 0;
}