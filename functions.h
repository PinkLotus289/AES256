

#define BUFFER_SIZE 1024
#define KEY_SIZE 32  // 256 бит = 32 байта
#define IV_SIZE 16   // 128 бит = 16 байт

typedef struct {
    unsigned char key[KEY_SIZE + 1]; // 256 бит = 32 байта + 1 для '\0'
    unsigned char iv[IV_SIZE + 1];   // 128 бит = 16 байт + 1 для '\0'
} CryptoParams;

typedef struct {
    CryptoParams params;
    unsigned char text[BUFFER_SIZE];
    unsigned char ciphertext[BUFFER_SIZE];
    unsigned char decryptedtext[BUFFER_SIZE];
    int text_len;
    int ciphertext_len;
    int decryptedtext_len;
} CryptoData;

void handleErrors(void);

int encrypt(const CryptoParams *params, const unsigned char *plaintext, int plaintext_len, unsigned char *ciphertext);

int decrypt(const CryptoParams *params, const unsigned char *ciphertext, int ciphertext_len, unsigned char *plaintext);

void print_hex(const unsigned char *data, int len);

int hex_to_bytes(const char *hex, unsigned char *bytes, int max_len);

void read_input(const char *prompt, unsigned char *buffer, int size);

void read_fixed_length_input(const char *prompt, unsigned char *buffer, int size);

void clear_input_buffer();

int read_key_file(const char *filename, CryptoParams *params);