#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <ctype.h>
#include <cuda_runtime.h>
#include <time.h>

#define MAX_INPUT_LENGTH 1000000 // Max length for each line in encrypted data

__device__ unsigned char hexCharToValue(char hexChar) {
	if (hexChar >= '0' && hexChar <= '9') {
	    return hexChar - '0';
	}
	else if (hexChar >= 'A' && hexChar <= 'F') {
	    return hexChar - 'A' + 10;
	}
	else if (hexChar >= 'a' && hexChar <= 'f') {
	    return hexChar - 'a';
	}
	return 0;
}

__global__ void hex_to_bin_kernel(const char *hex, unsigned char *bin, int hex_len) {
    int idx = blockDim.x * blockIdx.x + threadIdx.x;

    if (idx < hex_len / 2) {
	unsigned char highNibble = hexCharToValue(hex[idx * 2]);
	unsigned char lowNibble = hexCharToValue(hex[idx * 2 + 1]);
	bin[idx] = (highNibble << 4) | lowNibble;
    }
}

int cuda_hex_to_bin(const char *hex, unsigned char *bin, int bin_size) {
    int hex_len = strlen(hex);
    if (hex_len % 2 != 0 || bin_size < hex_len / 2) {
        return -1;
    }

    char *d_hex;
    unsigned char *d_bin;

    cudaMalloc((void **)&d_hex, hex_len * sizeof(char));
    cudaMalloc((void **)&d_bin, (hex_len / 2) * sizeof(unsigned char));

    cudaMemcpy(d_hex, hex, hex_len * sizeof(char), cudaMemcpyHostToDevice);

    int threadsPerBlock = 256;
    int blocksPerGrid = (hex_len / 2 + threadsPerBlock - 1) / threadsPerBlock;

    hex_to_bin_kernel<<<blocksPerGrid, threadsPerBlock>>>(d_hex, d_bin, hex_len);
    cudaDeviceSynchronize();

    cudaMemcpy(bin, d_bin, (hex_len / 2) * sizeof(unsigned char), cudaMemcpyDeviceToHost);

    cudaFree(d_hex);
    cudaFree(d_bin);

    return hex_len / 2;
}

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
                printf("%s|%s|%s\n", original_hex, password, decryptedtext);
                return 0; // Return success for this password
            }
        }
    }

    return -1; // Decryption failed with this password
}

// Main function to handle input from file and passwords
int main(int argc, char *argv[]) {
    if (argc != 4) { // Expect a third argument for iterations
        fprintf(stderr, "Usage: %s <hex input file> <password list file> <iterations>\n", argv[0]);
        return 1;
    }

    char *filename = argv[1];
    char *password_file = argv[2];
    int iterations = atoi(argv[3]); // Convert the third argument to an integer
    if (iterations <= 0) {
        fprintf(stderr, "Invalid iterations value. Must be a positive integer.\n");
        return 1;
    }

    unsigned char encrypted_data[MAX_INPUT_LENGTH / 2]; // To hold up to 100000/2 bytes of decoded binary data
    char hex_line[MAX_INPUT_LENGTH]; // Buffer to hold each hex-encoded line

    FILE *file = fopen(filename, "r");
    if (!file) {
        fprintf(stderr, "Error opening encrypted data file: %s\n", filename);
        return 1;
    }

    FILE *passwords = fopen(password_file, "r");
    if (!passwords) {
        fprintf(stderr, "Error opening password file: %s\n", password_file);
        fclose(file);
        return 1;
    }

    // Read each line from the encrypted data file
    while (fgets(hex_line, sizeof(hex_line), file)) {
        // Remove newline character if present
        size_t len = strlen(hex_line);
        if (hex_line[len - 1] == '\n') {
            hex_line[len - 1] = '\0';
        }

        // Convert the hex-encoded line to binary
        int encrypted_len;
	clock_t start_time = clock();

#if 1
	encrypted_len = hex_to_bin(hex_line, encrypted_data, sizeof(encrypted_data));
#else
	encrypted_len = cuda_hex_to_bin(hex_line, encrypted_data, sizeof(encrypted_data));
#endif
	printf("time: %f\n", ((double)(clock() - start_time)) / CLOCKS_PER_SEC);

        if (encrypted_len < 0) {
            continue;
        }

        // Reset password file pointer for every new line in the encrypted data file
        fseek(passwords, 0, SEEK_SET);

        // Try each password from the password list
        char password[256];
        while (fgets(password, sizeof(password), passwords)) {
            // Remove newline character if present
            size_t pass_len = strlen(password);
            if (password[pass_len - 1] == '\n') {
                password[pass_len - 1] = '\0';
            }

            // Perform decryption with this password
            if (perform_decryption(encrypted_data, encrypted_len, (unsigned char *)password, hex_line, iterations) == 0) {
                break; // Move to the next encrypted line
            }
        }
    }

    fclose(file);
    fclose(passwords);
    return 0;
}

