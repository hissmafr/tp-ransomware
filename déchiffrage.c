#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <dirent.h>
#include <sys/stat.h>

// Affiche les erreurs OpenSSL et termine le programme.

void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

void decrypt_file(const char *input_path, const unsigned char *key, const unsigned char *iv) {
    FILE *f_in, *f_out;
    int in_len, out_len;
    unsigned char inbuf[1024], outbuf[1024 + EVP_MAX_BLOCK_LENGTH];
    EVP_CIPHER_CTX *ctx;

    // Construire le chemin du fichier de sortie en retirant l'extension .enc
    char output_path[256];
    strncpy(output_path, input_path, strlen(input_path) - 4);
    output_path[strlen(input_path) - 4] = '\0';

    if(!(f_in = fopen(input_path, "rb"))) {
        perror("Erreur lors de l'ouverture du fichier d'entrée");
        return;
    }

    if(!(f_out = fopen(output_path, "wb"))) {
        perror("Erreur lors de l'ouverture du fichier de sortie");
        fclose(f_in);
        return;
    }

    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) handleErrors();

    while((in_len = fread(inbuf, 1, 1024, f_in)) > 0) {
        if(1 != EVP_DecryptUpdate(ctx, outbuf, &out_len, inbuf, in_len)) handleErrors();
        fwrite(outbuf, 1, out_len, f_out);
    }

    if(EVP_DecryptFinal_ex(ctx, outbuf + out_len, &out_len)) {
        fwrite(outbuf, 1, out_len, f_out);
        // Suppression du fichier .enc après un déchiffrement réussi
        remove(input_path);
    } else {
        ERR_print_errors_fp(stderr);
    }

    EVP_CIPHER_CTX_free(ctx);
    fclose(f_in);
    fclose(f_out);
}

void decrypt_directory(const char *directory_path, const unsigned char *key, const unsigned char *iv) {
    DIR *dir;
    struct dirent *entry;
    char path[1024];

    if(!(dir = opendir(directory_path))) {
        perror("Erreur lors de l'ouverture du répertoire");
        return;
    }

    while((entry = readdir(dir)) != NULL) {
        if(strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;

        snprintf(path, sizeof(path), "%s/%s", directory_path, entry->d_name);

        struct stat path_stat;
        stat(path, &path_stat);

        if(S_ISDIR(path_stat.st_mode)) {
            decrypt_directory(path, key, iv);
        } else {
            // Vérifie si le fichier a une extension .enc
            if(strstr(entry->d_name, ".enc") != NULL) {
                printf("Déchiffrement de : %s\n", path);
                decrypt_file(path, key, iv);
            }
        }
    }
    closedir(dir);
}

int main(int argc, char *argv[]) {
    if(argc != 2) {
        fprintf(stderr, "Utilisation: %s <chemin_du_répertoire>\n", argv[0]);
        return 1;
    }

    unsigned char key[32], iv[16];

    FILE *file_key = fopen("key.bin", "rb");
    FILE *file_iv = fopen("iv.bin", "rb");
    if(!file_key || !file_iv) {
        perror("Erreur lors de l'ouverture des fichiers de clé/IV");
        return 1;
    }
    fread(key, 1, sizeof(key), file_key);
    fread(iv, 1, sizeof(iv), file_iv);
    fclose(file_key);
    fclose(file_iv);

    decrypt_directory(argv[1], key, iv);

    printf("Déchiffrement terminé.\n");

    return 0;
}

