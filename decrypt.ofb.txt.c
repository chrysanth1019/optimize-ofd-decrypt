#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <ctype.h>
// #include <cuda_runtime.h>
#include <pthread.h>
#include <unistd.h>
#include <mpi.h>

#define MAX_INPUT_LENGTH 1000000 // Max length for each line in encrypted data

// Base58 alphabet
const char *base58_alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

#define hex2char(c, b) do { \
    if (c >= '0' && c <= '9') { \
        b = c - '0'; \
    } else if (c >= 'A' && c <= 'F') { \
        b = c - 'A' + 10; \
    } else if (c >= 'a' && c <= 'f') { \
        b = c - 'a' + 10; \
    } else { \
	b = 0; \
    } \
} while(0)

// Function to convert hex string to binary data
int hex_to_bin(const char *hex, unsigned char *bin, int bin_size) {
    int hex_len = strlen(hex);
    if (hex_len % 2 != 0) {
        return -1;
    }

    if (bin_size < hex_len / 2) {
        return -1;
    }

    for (int i = 0; i < hex_len / 2; i++) {
#if 1
	unsigned char highNibble, lowNibble;
	hex2char(hex[i * 2], highNibble);
	hex2char(hex[i * 2 + 1], lowNibble);
	bin[i] = (highNibble << 4) | lowNibble;
#else
        sscanf(&hex[i * 2], "%2hhx", &bin[i]);
#endif
    }

    return hex_len / 2;
}

// Check if a block of data is all ASCII
int is_all_ascii(unsigned char *data, int len) {
    for (int i = 0; i < len; i++) {
        if (data[i] < 0 || data[i] > 127) {
            return 0; // Not ASCII
        }
    }
    return 1; // All ASCII
}

// Remove different padding schemes
void remove_padding(unsigned char *data, int *data_len, int padding_type) {
    int padding_len;
    switch (padding_type) {
        case 1: // NoPadding
            break;
    }
}

// Define the AES decryption function with various modes and paddings
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *password, unsigned char *iv, unsigned char *plaintext, const EVP_CIPHER *cipher, int padding_type, int iterations) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    unsigned char key[32];

    // Derive key using PBKDF2 with user-provided iterations
    if (!PKCS5_PBKDF2_HMAC_SHA1((char *)password, strlen((char *)password), iv, 16, iterations, sizeof(key), key)) {
        return -1;
    }

    // Create and initialize the context
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        return -1;
    }

    // Initialize the decryption operation
    if (1 != EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Set padding
    EVP_CIPHER_CTX_set_padding(ctx, padding_type == 6); // Only enable built-in PKCS7 padding for padding_type 6

    // Provide the message to be decrypted and obtain the plaintext output
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len = len;

    // Finalize the decryption
    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len += len;

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    // Remove padding if necessary
    if (padding_type != 6) {
        remove_padding(plaintext, &plaintext_len, padding_type);
    }

    return plaintext_len;
}

// Function to sanitize decrypted text (remove weird chars that create new lines or big spaces)
void sanitize_text(unsigned char *text, int len) {
    for (int i = 0; i < len; i++) {
        // If character is not printable, replace it with a space
        if (text[i] < 32 || text[i] > 126) {
            text[i] = ' ';
        }
    }
    text[len] = '\0'; // Null-terminate the string after sanitization
}

// Function to perform the decryption and handle the different modes and paddings
int perform_decryption(unsigned char *ciphertext, int ciphertext_len, unsigned char *password, char *original_hex, int iterations) {
    unsigned char iv[16]; // Initialize IV buffer
    unsigned char decryptedtext[2048000];
    int decryptedtext_len;
    const EVP_CIPHER *modes[] = {
        EVP_aes_256_ofb(), // Use OFB mode
    };
    int paddings[] = {1}; // Only NoPadding

    // Extract IV from the beginning of the ciphertext for modes that require it
    for (int i = 0; i < sizeof(modes) / sizeof(modes[0]); i++) {
        int iv_len = EVP_CIPHER_iv_length(modes[i]);
        unsigned char *ciphertext_copy = ciphertext;
        int ciphertext_len_copy = ciphertext_len;

        if (iv_len > 0) {
            memcpy(iv, ciphertext, iv_len);
            ciphertext_copy += iv_len;
            ciphertext_len_copy -= iv_len;
        } else {
            memset(iv, 0, sizeof(iv)); // Set IV to zero for ECB mode
        }

        for (int j = 0; j < sizeof(paddings) / sizeof(paddings[0]); j++) {
            decryptedtext_len = decrypt(ciphertext_copy, ciphertext_len_copy, (unsigned char *)password, iv, decryptedtext, modes[i], paddings[j], iterations);
            if (decryptedtext_len > 0 && is_all_ascii(decryptedtext, decryptedtext_len)) {
                sanitize_text(decryptedtext, decryptedtext_len);

                // Output hexencoded data | password | decrypted data
                // printf("%s|%s|%s\n", original_hex, password, decryptedtext);
                return 0; // Return success for this password
            }
        }
    }

    return -1; // Decryption failed with this password
}

typedef struct _password {
    char *password;
    struct _password *next;
} _password;

_password *password_head = 0;
_password *password_tail = 0;


typedef struct _hash {
    char *buf;
    struct _hash *next;
} _hash;

_hash *hash_head = 0;
_hash *hash_tail = 0;
pthread_mutex_t hash_mutex;


int load_password(char *file) {
    FILE *fp = fopen(file, "r");
    if (!fp) {
        return -1;
    }
    char buf[0x200];
    while (fgets(buf, sizeof(buf) - 1, fp)) {
        size_t pass_len = strlen(buf);
        if (pass_len == 0) {
            continue;
        }
        if (buf[pass_len - 1] == '\n') {
            buf[pass_len - 1] = '\0';
        }
        if (pass_len == 0) {
            continue;
        }
        _password *i = (_password *)malloc(sizeof(_password));
        memset(i, 0, sizeof(_password));
        i->password = (char *)malloc(pass_len + 1);
        memset(i->password, 0, pass_len + 1);
        strcpy(i->password, buf);
        i->next = 0;

        if (password_head) {
            password_tail->next = i;
        }
        else {
            password_head = i;
            password_tail = i;
        }
    }
    fclose(fp);
    return 0;
}

int exit_loop = 0;
void* thread_function(void* arg) {
    int idx = (int)arg;
    // Convert the hex-encoded line to binary
    int encrypted_len;
    unsigned char encrypted_data[MAX_INPUT_LENGTH / 2] = {0}; // To hold up to 100000/2 bytes of decoded binary data
    int n = 0;
    while(1) {
        if (exit_loop) {
            break;
        }
        _hash *v = 0;
        pthread_mutex_lock(&hash_mutex);
        if (hash_head == 0) {
            pthread_mutex_unlock(&hash_mutex);
            break;
        }
        v = hash_head;
        hash_head = hash_head->next;
        pthread_mutex_unlock(&hash_mutex);
        if ((n % 8) != idx) {
            n++;
            continue;
        }
        n++;
    #if 1
        encrypted_len = hex_to_bin(v->buf, encrypted_data, sizeof(encrypted_data));
    #else
        encrypted_len = cuda_hex_to_bin(hex_line, encrypted_data, sizeof(encrypted_data));
    #endif
        if (encrypted_len < 0) {
            continue;
        }
        // Try each password from the password list
        char password[256];
        _password *pass = password_head;
        clock_t start_time = clock();
        while(pass) {
            if (perform_decryption(encrypted_data, encrypted_len, (unsigned char *)pass->password, v->buf, /*iterations*/1) == 0) {
                break;
            }
            pass = pass->next;
        }
        // printf("time: %f\n", ((double)(clock() - start_time)) / CLOCKS_PER_SEC);
    }
}

// Main function to handle input from file and passwords
int main(int argc, char *argv[]) {
    MPI_Init(&argc, &argv);

    int world_size, world_rank;
    MPI_Comm_size(MPI_COMM_WORLD, &world_size);
    MPI_Comm_rank(MPI_COMM_WORLD, &world_rank);
    printf("Process %d of %d is running on CPU\n", world_rank + 1, world_size);


    if (argc != 4) { // Expect a third argument for iterations
        fprintf(stderr, "Usage: %s <hex input file> <password list file> <iterations>\n", argv[0]);
        return 1;
    }

    if (pthread_mutex_init(&hash_mutex, NULL) != 0) {
        printf("Mutex initialization failed\n");
        return -1;
    }
    char *filename = argv[1];
    int iterations = atoi(argv[3]); // Convert the third argument to an integer
    if (iterations <= 0) {
        fprintf(stderr, "Invalid iterations value. Must be a positive integer.\n");
        return 1;
    }

    char hex_line[MAX_INPUT_LENGTH]; // Buffer to hold each hex-encoded line

    FILE *file = fopen(filename, "r");
    if (!file) {
        fprintf(stderr, "Error opening encrypted data file: %s\n", filename);
        return 1;
    }

    if (load_password(argv[2]) == -1) {
        fclose(file);
        fprintf(stderr, "Error opening password file: %s\n", argv[2]);
        return 1;
    }

    
    int n = 0;
    // Read each line from the encrypted data file
    while (fgets(hex_line, sizeof(hex_line), file)) {
        // Remove newline character if present
        size_t len = strlen(hex_line);
        if (hex_line[len - 1] == '\n') {
            hex_line[len - 1] = '\0';
        }

        char *buf = (char *)malloc(len + 1);
        memset(buf, 0, len + 1);
        strcpy(buf, hex_line);

        _hash *node = (_hash *)malloc(sizeof(_hash));
        memset(node, 0, sizeof(_hash));
        node->buf = buf;
        node->next = 0;

        if (hash_head == 0) {
            hash_head = node;
            hash_tail = node;
        }
        else {
            hash_tail->next = node;
            hash_tail = node;
        }
    }
    fclose(file);

    clock_t start_time = clock();

#if 1
    thread_function((void *)world_rank);
#else

    pthread_t threads[0x4];
    for (int i = 0; i < sizeof(threads) / sizeof(pthread_t); i++) {
        if (pthread_create(&threads[i], 0, &thread_function, (void *)world_rank) != 0) {
            printf("Failed to create thread %d\n", i + 1);
        }
    }

    for (int i = 0; i < sizeof(threads) / sizeof(pthread_t); i++) {
        pthread_join(threads[i], NULL);
    }
#endif
    printf("total: %f\n", ((double)(clock() - start_time)) / CLOCKS_PER_SEC);

    MPI_Finalize();
    return 0;
}

