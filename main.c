#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>


#include "functions.h"


int main()
{
    CryptoData data;
    int choice;
    char key_file[256];

    printf("Введите имя файла с ключом и вектором инициализации: ");
    scanf("%255s", key_file);
    clear_input_buffer();

    if (read_key_file(key_file, &data.params) != 0) {
        return 1;
    }

    printf("Выберите действие:\n");
    printf("1. Зашифровать текст\n");
    printf("2. Дешифровать текст\n");
    printf("Ваш выбор: ");
    scanf("%d", &choice);
    getchar();  // Очистка буфера ввода

    if (choice == 1) {
        read_input("Введите текст (не более 1023 символов): ", data.text, BUFFER_SIZE - 1);
        data.text_len = strlen((char *)data.text);

        // Зашифрование
        data.ciphertext_len = encrypt(&data.params, data.text, data.text_len, data.ciphertext);
        printf("Зашифрованный текст (в шестнадцатеричном формате):\n");
        print_hex(data.ciphertext, data.ciphertext_len);
    } else if (choice == 2) {
        char hex_ciphertext[BUFFER_SIZE * 2];
        read_input("Введите шифрованный текст (в шестнадцатеричном формате): ", (unsigned char *)hex_ciphertext, sizeof(hex_ciphertext));

        data.ciphertext_len = hex_to_bytes(hex_ciphertext, data.ciphertext, BUFFER_SIZE);
        if (data.ciphertext_len < 0) {
            printf("Ошибка: неверный формат шестнадцатеричной строки.\n");
            return 1;
        }

        // Дешифрование
        data.decryptedtext_len = decrypt(&data.params, data.ciphertext, data.ciphertext_len, data.decryptedtext);
        if (data.decryptedtext_len < 0) {
            printf("Ошибка дешифрования.\n");
            return 1;
        }

        data.decryptedtext[data.decryptedtext_len] = '\0';
        printf("Дешифрованный текст:\n%s\n", data.decryptedtext);
    } else {
        printf("Неправильный выбор.\n");
        return 1;
    }

    // Безопасное очищение ключа и IV из памяти
    OPENSSL_cleanse(data.params.key, sizeof(data.params.key));
    OPENSSL_cleanse(data.params.iv, sizeof(data.params.iv));

    return 0;
}
