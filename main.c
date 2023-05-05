#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>

#include <openssl/evp.h>
#include <openssl/md4.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>

#define BUFSIZE 4096
#define MAX_LINE_LENGTH 1024

typedef struct HashAlgorithm {
    char *name;
    size_t digest_length;
    void (*init)(void *);
    void (*update)(void *, const void *, size_t);
    void (*final)(unsigned char *, void *);
} HashAlgorithm;

HashAlgorithm ALGORITHMS[] = {
    {"MD4", MD4_DIGEST_LENGTH, (void *)MD4_Init, (void *)MD4_Update, (void *)MD4_Final},
    {"MD5", MD5_DIGEST_LENGTH, (void *)MD5_Init, (void *)MD5_Update, (void *)MD5_Final},
    {"SHA1", SHA_DIGEST_LENGTH, (void *)SHA1_Init, (void *)SHA1_Update, (void *)SHA1_Final},
    {"SHA224", SHA224_DIGEST_LENGTH, (void *)SHA224_Init, (void *)SHA224_Update, (void *)SHA224_Final},
    {"SHA256", SHA256_DIGEST_LENGTH, (void *)SHA256_Init, (void *)SHA256_Update, (void *)SHA256_Final},
    {"SHA384", SHA384_DIGEST_LENGTH, (void *)SHA384_Init, (void *)SHA384_Update, (void *)SHA384_Final},
    {"SHA512", SHA512_DIGEST_LENGTH, (void *)SHA512_Init, (void *)SHA512_Update, (void *)SHA512_Final},
    {"RIPEMD160", RIPEMD160_DIGEST_LENGTH, (void *)RIPEMD160_Init, (void *)RIPEMD160_Update, (void *)RIPEMD160_Final}/*,
    {"BLAKE2s-256", BLAKE2S256_DIGEST_LENGTH, (void *)blake2s_init, (void *)blake2s_update, (void *)blake2s_final},
    {"BLAKE2b-256", BLAKE2B256_DIGEST_LENGTH, (void *)blake2b_init, (void *)blake2b_update, (void *)blake2b_final},
    {"BLAKE2b-384", BLAKE2B384_DIGEST_LENGTH, (void *)blake2b_init, (void *)blake2b_update, (void *)blake2b_final},
    {"BLAKE2b-512", BLAKE2B512_DIGEST_LENGTH, (void *)blake2b_init, (void *)blake2b_update, (void *)blake2b_final}*/
};

size_t num_algorithms = sizeof(ALGORITHMS) / sizeof(HashAlgorithm);

char *hashType;
char **wordlistFiles;
int num_wordlist_files = 0;
char *encoded;

bool help = false;
bool listHashes = false;

void showLogo() {
    printf(" __ __   ____    __  __ __   ____  \n");
    printf("|  |  | /    |  /  ]|  |  | /    | \n");
    printf("|  |  ||  o  | /  / |  |  ||  o  | \n");
    printf("|  _  ||     |/  /  |  _  ||     | \n");
    printf("|  |  ||  _  /   \\_ |  |  ||  _  | \n");
    printf("|  |  ||  |  \\     ||  |  ||  |  | \n");
    printf("|__|__||__|__|\\____||__|__||__|__| \n");
    printf("                                   \n");
    printf("    __  ____    ____  __ __  __  _ \n");
    printf("   /  ]|    \\  /    ||  |  ||  |/ ]\n");
    printf("  /  / |  D  )|  o  ||  |  ||  ' / \n");
    printf(" /  /  |    / |     ||_   _||    \\ \n");
    printf("/   \\_ |    \\ |  _  ||     ||     \\\n");
    printf("\\     ||  .  \\|  |  ||  |  ||  .  |\n");
    printf(" \\____||__|\\_||__|__||__|__||__|\\_|\n");
    printf("                                   \n");
    printf("- Coded with <3 by Arhoc.\n");
    printf("                                   \n");
    printf("                                   \n");
    
    
}

void showHelp(char* pName) {
    printf("Usage:\n");
    printf("\t--hash\tThe hash type (MD5, SHA1, etc.)\n");
    printf("\t--wlist\tThe wordlist(s) to bruteforce\n");
    printf("\t--list\tList compatible hashes\n");

    printf("Examples:\n");
    printf("\t%s --wlist=/usr/share/wordlists/rockyou.txt --hash=sha256 4980b1f29fa32ff18c95d0ed931fd48e1ad43a729251d6eddb3cece705ed4d05\n", pName);
    printf("\t%s --wlist /usr/share/wordlists/rockyou.txt --hash md5 63e780c3f321d13109c71bf81805476e\n", pName);
    printf("\t%s --wlist=myWordlist.txt --hash=sha1 myHashFile.txt\n", pName);
}

void showAvailableHashes() {
    printf("These are the available hashes that I can crack:\n");
    for(int i = 0; i < num_algorithms; i++) {
        printf("\t- %s\n", ALGORITHMS[i].name);
    }
}


bool textToHash(char *plaintext, HashAlgorithm algorithm, char **hashValue) {
    EVP_MD_CTX *mdctx;
    const EVP_MD *md;
    unsigned char *hash;

    
    md = EVP_get_digestbyname(algorithm.name);
    if(md == NULL) {
        printf("Error: Algoritmo de hash desconocido\n");
        return false;
    }

    mdctx = EVP_MD_CTX_new();
    if(mdctx == NULL) {
        printf("Error: No se pudo inicializar el contexto de hash\n");
        return false;
    }

    
    if(EVP_DigestInit_ex(mdctx, md, NULL) != 1) {
        printf("Error: No se pudo asociar el contexto de hash con el algoritmo seleccionado\n");
        return false;
    }

    
    if(EVP_DigestUpdate(mdctx, plaintext, strlen(plaintext)) != 1) {
        printf("Error: No se pudo procesar el texto plano\n");
        return false;
    }

    
    hash = (unsigned char *)malloc(algorithm.digest_length);
    if(EVP_DigestFinal_ex(mdctx, hash, NULL) != 1) {
        printf("Error: No se pudo finalizar el hash\n");
        return false;
    }

    
    char *hashHex = (char *)malloc(algorithm.digest_length * 2 + 1);
    for(int i = 0; i < algorithm.digest_length; i++) {
        sprintf(hashHex + (i * 2), "%02x", hash[i]);
    }
    hashHex[algorithm.digest_length * 2] = '\0';
    *hashValue = hashHex;

    
    free(hash);
    EVP_MD_CTX_free(mdctx);

    return true;
}

void parseArgs(int argc, char ** argv) {
    int i;
    for (i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--hash") == 0) {
            hashType = argv[i + 1];
        } else if (strcmp(argv[i], "--wlist") == 0) {
            for (int w = i + 1; w < argc; w++) {
                if (strcmp(argv[w], "--hash") == 0) {
                    break;
                }
                num_wordlist_files++;
                wordlistFiles = (char ** ) realloc(wordlistFiles, num_wordlist_files * sizeof(char * ));
                wordlistFiles[num_wordlist_files - 1] = argv[w];
            }
            i += num_wordlist_files;

        } else if (strcmp(argv[i], "--list") == 0) {
            listHashes = true;
        } else if (strcmp(argv[i], "--help") == 0) {
            help = true;
        }
    }

    if (!hashType || num_wordlist_files == 0) {
        showHelp(argv[0]);
        exit(1);
    }
}

int lineCount(FILE *fp) {
    int count = 0;
    char ch;

    while (!feof(fp)) {
        ch = fgetc(fp);

        if (ch == '\n') {
            count++;
        }
    }

    if (ch != '\n' && count != 0) {
        count++;
    }

    rewind(fp);
    return count;
}


int main(int argc, char ** argv) {
    showLogo();

    parseArgs(argc, argv);
    encoded = argv[argc - 1];

    if (help) {
        showHelp(argv[0]);
        return 0;
    }

    if (listHashes) {
        showAvailableHashes();
        return 0;
    }

    for (int k = 0; k < num_algorithms; k++) {
        if (strcmp(hashType, ALGORITHMS[k].name) == 0) {
            FILE * fp;

            printf("[-] Hang on, we're breaking your hash...\n");

            for (int i = 0; i < num_wordlist_files; i++) {
                fp = fopen(wordlistFiles[i], "r");
                char buf[MAX_LINE_LENGTH];

                if (fp == NULL) {
                    printf("Error al abrir el archivo %s\n", wordlistFiles[i]);
                    exit(EXIT_FAILURE);
                }

                printf("[-] Trying to break %s with %d words...\n", encoded, lineCount(fp));
                
                while (fgets(buf, MAX_LINE_LENGTH, fp) != NULL) {
                    size_t length = strcspn(buf, "\n");
                    char line[length + 1];
                    strncpy(line, buf, length);
                    line[length] = '\0';

                    char * hashValue;
                    textToHash(line, ALGORITHMS[k], & hashValue);

                    if (strcmp(encoded, hashValue) == 0) {
                        printf("[!] The decoded hash is: %s\n", line);
                        return 0;
                    }
                }

                printf("[?] Hash not found\n");

                fclose(fp);
            }
        }
    }

    return 1;
}