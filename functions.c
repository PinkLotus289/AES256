#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include "functions.h"

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

int encrypt(const CryptoParams *params, const unsigned char *plaintext, int plaintext_len, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    if (!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, params->key, params->iv))
        handleErrors();

    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int decrypt(const CryptoParams *params, const unsigned char *ciphertext, int ciphertext_len, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    if (!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, params->key, params->iv))
        handleErrors();

    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleErrors();
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

void print_hex(const unsigned char *data, int len)
{
    for (int i = 0; i < len; i++)
        printf("%02x", data[i]);
    printf("\n");
}

int hex_to_bytes(const char *hex, unsigned char *bytes, int max_len)
{
    int hex_len = strlen(hex);
    if (hex_len % 2 != 0 || hex_len / 2 > max_len)
        return -1;76 

    for (int i = 0; i < hex_len / 2; i++) {
        sscanf(&hex[i * 2], "%2hhx", &bytes[i]);
    }
    return hex_len / 2;
}

void read_input(const char *prompt, unsigned char *buffer, int size)
{
    printf("%s", prompt);
    if (fgets((char *)buffer, size + 1, stdin) != NULL) {
        size_t len = strlen((char *)buffer);
        if (len > 0 && buffer[len - 1] == '\n')
            buffer[len - 1] = '\0';
    }
}

void read_fixed_length_input(const char *prompt, unsigned char *buffer, int size)
{
    while (1) {
        read_input(prompt, buffer, size);
        if (strlen((char *)buffer) == size) {
            break;
        } else {
            printf("Ошибка: длина должна быть ровно %d символов. Попробуйте снова.\n", size);
        }
    }
}

void clear_input_buffer()
{
    int c;
    while ((c = getchar()) != '\n' && c != EOF);
}

int read_key_file(const char *filename, CryptoParams *params)
{
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("Ошибка открытия файла");
        return -1;
    }

    if (fgets((char *)params->key, KEY_SIZE + 2, file) == NULL) { // KEY_SIZE + 2 to accommodate '\n' and '\0'
        perror("Ошибка чтения ключа из файла");
        fclose(file);
        return -1;
    }

    size_t key_len = strlen((char *)params->key);
    if (key_len > 0 && params->key[key_len - 1] == '\n') {
        params->key[key_len - 1] = '\0';
    }

    if (strlen((char *)params->key) != KEY_SIZE) {
        printf("Ошибка: длина ключа в файле должна быть ровно %d символов.\n", KEY_SIZE);
        fclose(file);
        return -1;
    }

    if (fgets((char *)params->iv, IV_SIZE + 2, file) == NULL) { // IV_SIZE + 2 to accommodate '\n' and '\0'
        perror("Ошибка чтения вектора инициализации из файла");
        fclose(file);
        return -1;
    }

    size_t iv_len = strlen((char *)params->iv);
    if (iv_len > 0 && params->iv[iv_len - 1] == '\n') {
        params->iv[iv_len - 1] = '\0';
    }

    if (strlen((char *)params->iv) != IV_SIZE) {
        printf("Ошибка: длина вектора инициализации в файле должна быть ровно %d символов.\n", IV_SIZE);
        fclose(file);
        return -1;
    }

    fclose(file);
    return 0;
}