#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <sys/stat.h>

#include <openssl/evp.h>
#include <openssl/md4.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>

#define BUFSIZE 4096
#define MAX_LINE_LENGTH 1024
#define MAX_HASH_LENGTH 128

typedef struct {
    const char *name;
    size_t digest_length;
    const EVP_MD *(*get_md)(void);
} HashAlgorithm;

static const HashAlgorithm ALGORITHMS[] = {
    {"MD4", MD4_DIGEST_LENGTH, EVP_md4},
    {"MD5", MD5_DIGEST_LENGTH, EVP_md5},
    {"SHA1", SHA_DIGEST_LENGTH, EVP_sha1},
    {"SHA224", SHA224_DIGEST_LENGTH, EVP_sha224},
    {"SHA256", SHA256_DIGEST_LENGTH, EVP_sha256},
    {"SHA384", SHA384_DIGEST_LENGTH, EVP_sha384},
    {"SHA512", SHA512_DIGEST_LENGTH, EVP_sha512},
    {"RIPEMD160", RIPEMD160_DIGEST_LENGTH, EVP_ripemd160}
};

static const size_t num_algorithms = sizeof(ALGORITHMS) / sizeof(HashAlgorithm);

static void show_logo(void) {
    printf("\033[1;33m __ __   ____    __  __ __   ____  \n");
    printf("|  |  | /    |  /  ]|  |  | /    | \n");
    printf("|  |  ||  o  | /  / |  |  ||  o  | \n");
    printf("|  _  ||     |/  /  |  _  ||     | \n");
    printf("|  |  ||  _  /   \\_ |  |  ||  _  | \n");
    printf("|  |  ||  |  \\     ||  |  ||  |  | \n");
    printf("|__|__||__|__|\\____||__|__||__|__| \033[0m\n");
    printf("\033[1;31m    __  ____    ____  __ __  __  _ \n");
    printf("   /  ]|    \\  /    ||  |  ||  |/ ]\n");
    printf("  /  / |  D  )|  o  ||  |  ||  ' / \n");
    printf(" /  /  |    / |     ||_   _||    \\ \n");
    printf("/   \\_ |    \\ |  _  ||     ||     \\\n");
    printf("\\     ||  .  \\|  |  ||  |  ||  .  |\n");
    printf(" \\____||__|\\_||__|__||__|__||__|\\_|\033[0m\n");
    printf("\033[35m- Coded with <3 by Arhoc.\033[0m\n\n");
}

static void show_help(const char *prog_name) {
    printf("\033[1;33mUsage:\033[0m %s [OPTIONS] HASH\n\n", prog_name);
    printf("\033[1;33mOptions:\033[0m\n");
    printf("  \033[36m--hash TYPE\033[0m     Hash algorithm to use (required)\n");
    printf("  \033[36m--wlist FILE\033[0m    Wordlist file (can specify multiple)\n");
    printf("  \033[36m--list\033[0m          List available hash algorithms\n");
    printf("  \033[36m--help\033[0m          Show this help message\n");
    printf("\n\033[1;33mExamples:\033[0m\n");
    printf("  \033[32m%s\033[0m \033[36m--wlist rockyou.txt --hash SHA256 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8\033[0m\n", prog_name);
    printf("  \033[32m%s\033[0m \033[36m--wlist dict1.txt --wlist dict2.txt --hash MD5 098f6bcd4621d373cade4e832627b4f6\033[0m\n", prog_name);
}

static void show_available_hashes(void) {
    printf("\033[1;33mAvailable hash algorithms:\033[0m\n");
    for(size_t i = 0; i < num_algorithms; i++) {
        printf("  \033[1;31m- \033[1;37m%s\033[0m\n", ALGORITHMS[i].name);
    }
}

static bool is_valid_hash(const char *hash, size_t expected_len) {
    if(strlen(hash) != expected_len * 2) return false;
    
    for(size_t i = 0; i < expected_len * 2; i++) {
        if(!isxdigit(hash[i])) return false;
    }
    
    return true;
}

static bool compute_hash(const char *plaintext, const HashAlgorithm *algorithm, char *output) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if(!mdctx) return false;

    const EVP_MD *md = algorithm->get_md();
    if(!md) {
        EVP_MD_CTX_free(mdctx);
        return false;
    }

    if(EVP_DigestInit_ex(mdctx, md, NULL) != 1) {
        EVP_MD_CTX_free(mdctx);
        return false;
    }

    if(EVP_DigestUpdate(mdctx, plaintext, strlen(plaintext)) != 1) {
        EVP_MD_CTX_free(mdctx);
        return false;
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int len;
    if(EVP_DigestFinal_ex(mdctx, hash, &len) != 1) {
        EVP_MD_CTX_free(mdctx);
        return false;
    }

    for(unsigned int i = 0; i < len; i++) {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
    output[len * 2] = '\0';

    EVP_MD_CTX_free(mdctx);
    return true;
}

static size_t count_lines(FILE *fp) {
    size_t count = 0;
    char ch;

    while((ch = fgetc(fp)) != EOF) {
        if(ch == '\n') count++;
    }

    rewind(fp);
    return count;
}

static bool file_exists(const char *filename) {
    struct stat st;
    return stat(filename, &st) == 0;
}

static void str_toupper(char *str) {
    for(; *str; str++) *str = toupper(*str);
}

static void str_trim(char *str) {
    char *end = str + strlen(str) - 1;
    while(end >= str && isspace(*end)) end--;
    *(end + 1) = '\0';
}

int main(int argc, char **argv) {
    show_logo();

    if(argc < 2) {
        show_help(argv[0]);
        return EXIT_FAILURE;
    }

    const char *hash_type = NULL;
    char **wordlist_files = NULL;
    size_t num_wordlist_files = 0;
    bool list_hashes = false;
    const char *target_hash = NULL;

    for(int i = 1; i < argc; i++) {
        if(strcmp(argv[i], "--hash") == 0) {
            if(i + 1 >= argc) {
                fprintf(stderr, "\033[31m[!] Error: --hash requires an argument\033[0m\n");
                return EXIT_FAILURE;
            }
            hash_type = argv[++i];
            str_toupper((char *)hash_type);
        } 
        else if(strncmp(argv[i], "--wlist=", 8) == 0) {
            wordlist_files = realloc(wordlist_files, (num_wordlist_files + 1) * sizeof(char *));
            wordlist_files[num_wordlist_files++] = argv[i] + 8;
        }
        else if(strcmp(argv[i], "--wlist") == 0) {
            if(i + 1 >= argc) {
                fprintf(stderr, "\033[31m[!] Error: --wlist requires an argument\033[0m\n");
                return EXIT_FAILURE;
            }
            wordlist_files = realloc(wordlist_files, (num_wordlist_files + 1) * sizeof(char *));
            wordlist_files[num_wordlist_files++] = argv[++i];
        }
        else if(strcmp(argv[i], "--list") == 0) {
            list_hashes = true;
        }
        else if(strcmp(argv[i], "--help") == 0) {
            show_help(argv[0]);
            return EXIT_SUCCESS;
        }
        else if(argv[i][0] != '-') {
            target_hash = argv[i];
        }
        else {
            fprintf(stderr, "\033[31m[!] Error: Unknown option %s\033[0m\n", argv[i]);
            return EXIT_FAILURE;
        }
    }

    if(list_hashes) {
        show_available_hashes();
        return EXIT_SUCCESS;
    }

    if(!hash_type || num_wordlist_files == 0 || !target_hash) {
        show_help(argv[0]);
        return EXIT_FAILURE;
    }

    const HashAlgorithm *algorithm = NULL;
    for(size_t i = 0; i < num_algorithms; i++) {
        if(strcmp(hash_type, ALGORITHMS[i].name) == 0) {
            algorithm = &ALGORITHMS[i];
            break;
        }
    }

    if(!algorithm) {
        fprintf(stderr, "\033[31m[!] Error: Unsupported hash algorithm '%s'\033[0m\n", hash_type);
        show_available_hashes();
        return EXIT_FAILURE;
    }

    if(!is_valid_hash(target_hash, algorithm->digest_length)) {
        fprintf(stderr, "\033[31m[!] Error: Invalid hash format for %s (expected %zu hex chars)\033[0m\n", 
                algorithm->name, algorithm->digest_length * 2);
        return EXIT_FAILURE;
    }

    printf("\033[33m[-]\033[0m Target hash: %s (%s)\n", target_hash, algorithm->name);

    for(size_t i = 0; i < num_wordlist_files; i++) {
        if(!file_exists(wordlist_files[i])) {
            fprintf(stderr, "\033[31m[!] Error: Wordlist file '%s' not found\033[0m\n", wordlist_files[i]);
            continue;
        }

        FILE *fp = fopen(wordlist_files[i], "r");
        if(!fp) {
            fprintf(stderr, "\033[31m[!] Error: Could not open wordlist '%s'\033[0m\n", wordlist_files[i]);
            continue;
        }

        printf("\033[36m[?]\033[0m Using wordlist: %s\n", wordlist_files[i]);
        size_t total_words = count_lines(fp);
        printf("\033[33m[-]\033[0m Trying %zu words...\n", total_words);

        char line[MAX_LINE_LENGTH];
        size_t tried = 0;
        bool found = false;

        while(fgets(line, sizeof(line), fp)) {
            str_trim(line);
            tried++;

            if(tried % 100000 == 0) {
                printf("\033[33m[-]\033[0m Progress: %.2f%%\r", 
                      (double)tried / total_words * 100);
                fflush(stdout);
            }

            char computed_hash[MAX_HASH_LENGTH];
            if(!compute_hash(line, algorithm, computed_hash)) {
                fprintf(stderr, "\033[31m[!] Error computing hash for '%s'\033[0m\n", line);
                continue;
            }

            if(strcasecmp(target_hash, computed_hash) == 0) {
                printf("\n\033[32m[!]\033[0m Found match: \033[32m%s\033[0m\n", line);
                found = true;
                break;
            }
        }

        if(!found) {
            printf("\033[31m[!]\033[0m No match found in this wordlist\n\n");
        }

        fclose(fp);
        if(found) break;
    }

    free(wordlist_files);
    return EXIT_SUCCESS;
}
