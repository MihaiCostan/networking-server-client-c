#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <signal.h>

#define SERVER_FIFO_PATH "server_fifo"
#define CLIENT_FIFO_PATH "client_%d_fifo"

int shutdown_client = 0;

int main()
{
    pid_t pid = getpid();

    char fifo_client[64];
    snprintf(fifo_client, sizeof(fifo_client), CLIENT_FIFO_PATH, pid);
    if (mkfifo(fifo_client, 0666) == -1 && errno != EEXIST)
    {
        fprintf(stderr, "[CLIENT:%d]: Eroare la mkfifo propriu!\n", pid);
        exit(EXIT_FAILURE);
    }

    printf("\n------------------------------------------------------------------------------\n");
    printf("[CLIENT:%d]: S-a pornit clientul cu PID %d\n", pid, pid);
    printf("Comenzi utile:\n -->login : <username> <parola>\n -->get-logged-users\n -->get-proc-info : <target_proces pid>\n -->logout\n -->quit\n -->shutdown-server (admin protected command)\n");
    printf("\nIntroduceti comenzi: \n");

    char command[256];
    while (!shutdown_client)
    {
        printf("\n\n[CLIENT:%d]-->  ", pid);
        fflush(stdout);

        if (!fgets(command, sizeof(command), stdin))
            break;
        command[strcspn(command, "\n")] = '\0';

        int fd_server = open(SERVER_FIFO_PATH, O_WRONLY);
        if (fd_server == -1)
        {
            fprintf(stderr, "[CLIENT:%d]: Eroare! Serverul este inchis!!\n", pid);
            break;
        }

        char message[512];
        snprintf(message, sizeof(message), "%d;%s", pid, command);
        write(fd_server, message, strlen(message));
        close(fd_server);

        int fd_client = open(fifo_client, O_RDONLY);
        if (fd_client == -1)
        {
            fprintf(stderr, "[CLIENT:%d]: Eroare la deschiderea CLIENT_FIFO!\n", pid);
            break;
        }

        // citire lungime + raspuns;
        uint32_t lungime_network;
        read(fd_client, &lungime_network, sizeof(lungime_network));
        uint32_t lungime = ntohl(lungime_network);

        char *raspuns = malloc(lungime + 1);
        read(fd_client, raspuns, lungime);
        raspuns[lungime] = '\0';
        if (lungime > 0)
        {
            printf("\n>SERVER-RESPONSE(%u bytes):\n%s", lungime, raspuns);
            printf("------------------------------------------------------------------------------\n");
            if (strncmp(raspuns, "CLIENT QUIT! Goodbye!", 21) == 0 || strncmp(raspuns, "SHUTDOWN_SERVER", 15) == 0)
            {
                shutdown_client = 1;
                break;
            }
        }
        free(raspuns);
        close(fd_client);
    }
    unlink(fifo_client);
    return 0;
}