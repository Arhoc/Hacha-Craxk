#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <sys/stat.h>
#include <time.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <stdatomic.h>
#include <getopt.h>

#include <openssl/evp.h>
#include <openssl/md4.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>

#define BUFSIZE 4096
#define MAX_LINE_LENGTH 1024
#define MAX_HASH_LENGTH 128
#define MAX_THREADS 64
#define PROGRESS_UPDATE_INTERVAL 100000

typedef struct {
    const char *name;
    size_t digest_length;
    const EVP_MD *(*get_md)(void);
} HashAlgorithm;

typedef struct {
    const char *data;
    size_t data_size;
    size_t start_offset;
    size_t end_offset;
    const HashAlgorithm *algorithm;
    const char *target_hash;
    atomic_bool *found;
    char *result;
    pthread_mutex_t *result_mutex;
    atomic_size_t *total_tried;
    size_t total_words;
    time_t start_time;
} ThreadData;

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

static void show_logo() {
    printf(" __ __   ____    __  __ __   ____  \n");
    printf("|  |  | /    |  /  ]|  |  | /    | \n");
    printf("|  |  ||  o  | /  / |  |  ||  o  | \n");
    printf("|  _  ||     |/  /  |  _  ||     | \n");
    printf("|  |  ||  _  /   \\_ |  |  ||  _  | \n");
    printf("|  |  ||  |  \\     ||  |  ||  |  | \n");
    printf("|__|__||__|__|\\____||__|__||__|__| \n");
    printf("    __  ____    ____  __ __  __  _ \n");
    printf("   /  ]|    \\  /    ||  |  ||  |/ ]\n");
    printf("  /  / |  D  )|  o  ||  |  ||  ' / \n");
    printf(" /  /  |    / |     ||_   _||    \\ \n");
    printf("/   \\_ |    \\ |  _  |  |  | |     \\\n");
    printf("\\     ||  .  \\|  |  |  |  | |  .  |\n");
    printf(" \\____||__|\\_||__|__|  |__| |__|\\_|\n");
    printf("- Coded with <3 by Arhoc.\n\n");
}

static void show_help(const char *program_name) {
    printf("Usage: %s [OPTIONS] <hash>\n", program_name);
    printf("Options:\n");
    printf("  --wlist=<file>       Specify wordlist file\n");
    printf("  --hash=<type>        Specify hash type (MD5, SHA1, etc.)\n");
    printf("  --threads=<num>      Number of threads to use (default: 4)\n");
    printf("  --list-hashes        List supported hash algorithms\n");
    printf("  --help               Show this help message\n");
}

static void show_hashes() {
    printf("Supported hash algorithms:\n");
    for(size_t i = 0; i < num_algorithms; i++) {
        printf("  %s\n", ALGORITHMS[i].name);
    }
}

static bool file_exists(const char *filename) {
    struct stat st;
    return stat(filename, &st) == 0;
}

static bool is_valid_hash(const char *hash, const HashAlgorithm *algorithm) {
    size_t expected_len = algorithm->digest_length * 2;
    size_t actual_len = strlen(hash);
    
    if(actual_len != expected_len) {
        return false;
    }
    
    for(size_t i = 0; i < actual_len; i++) {
        if(!isxdigit(hash[i])) {
            return false;
        }
    }
    
    return true;
}

static bool compute_hash(const char *plaintext, const HashAlgorithm *algorithm, unsigned char *output) {
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

    unsigned int len;
    if(EVP_DigestFinal_ex(mdctx, output, &len) != 1) {
        EVP_MD_CTX_free(mdctx);
        return false;
    }

    EVP_MD_CTX_free(mdctx);
    return true;
}

static size_t count_lines_mmap(const char *data, size_t size) {
    size_t count = 0;
    for(size_t i = 0; i < size; i++) {
        if(data[i] == '\n') count++;
    }
    return count;
}

static void* crack_thread(void *arg) {
    ThreadData *data = (ThreadData *)arg;
    char line[MAX_LINE_LENGTH];
    unsigned char hash[EVP_MAX_MD_SIZE];
    char hash_str[MAX_HASH_LENGTH];
    size_t local_tried = 0;
    size_t pos = data->start_offset;
    
    if (pos > 0) {
        while (pos < data->end_offset && data->data[pos-1] != '\n') {
            pos++;
        }
    }
    
    while(pos < data->end_offset && !atomic_load(data->found)) {
        size_t line_start = pos;
        size_t line_len = 0;
        
        while (pos < data->end_offset && data->data[pos] != '\n' && line_len < MAX_LINE_LENGTH-1) {
            line[line_len++] = data->data[pos++];
        }
        line[line_len] = '\0';
        
        if (pos < data->end_offset && data->data[pos] == '\n') {
            pos++;
        }
        
        if (line_len == 0) continue;
        
        local_tried++;
        
        if(!compute_hash(line, data->algorithm, hash)) {
            continue;
        }
        
        for(unsigned int i = 0; i < data->algorithm->digest_length; i++) {
            sprintf(hash_str + (i * 2), "%02x", hash[i]);
        }
        
        if(memcmp(data->target_hash, hash_str, data->algorithm->digest_length * 2) == 0) {
            pthread_mutex_lock(data->result_mutex);
            if(!atomic_load(data->found)) {
                atomic_store(data->found, true);
                strncpy(data->result, line, MAX_LINE_LENGTH);
            }
            pthread_mutex_unlock(data->result_mutex);
            break;
        }
        
        if(local_tried % PROGRESS_UPDATE_INTERVAL == 0) {
            atomic_fetch_add(data->total_tried, PROGRESS_UPDATE_INTERVAL);
            
            if(pthread_self() % 4 == 0) {
                size_t tried = atomic_load(data->total_tried);
                double progress = (double)tried / data->total_words * 100;
                time_t now = time(NULL);
                double elapsed = difftime(now, data->start_time);
                double speed = tried / (elapsed ? elapsed : 1);
                double remaining = (data->total_words - tried) / speed;
                
                printf("\033[33m[-]\033[0m Progress: %.2f%% | Speed: %.0f hashes/sec | Elapsed: %.0fs | Remaining: %.0fs\r", 
                      progress, speed, elapsed, remaining);
                fflush(stdout);
            }
        }
    }
    
    atomic_fetch_add(data->total_tried, local_tried % PROGRESS_UPDATE_INTERVAL);
    
    return NULL;
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
    bool show_hashes_flag = false;
    const char *target_hash = NULL;
    int num_threads = 8;

    static struct option long_options[] = {
        {"wlist", required_argument, 0, 'w'},
        {"hash", required_argument, 0, 'h'},
        {"threads", required_argument, 0, 't'},
        {"list-hashes", no_argument, 0, 'l'},
        {"help", no_argument, 0, 'H'},
        {0, 0, 0, 0}
    };

    int opt;
    int option_index = 0;
    while((opt = getopt_long(argc, argv, "w:h:t:lH", long_options, &option_index)) != -1) {
        switch(opt) {
            case 'w':
                wordlist_files = realloc(wordlist_files, (num_wordlist_files + 1) * sizeof(char*));
                wordlist_files[num_wordlist_files++] = strdup(optarg);
                break;
            case 'h':
                hash_type = strdup(optarg);
                break;
            case 't':
                num_threads = atoi(optarg);
                if(num_threads < 1) num_threads = 1;
                if(num_threads > MAX_THREADS) num_threads = MAX_THREADS;
                break;
            case 'l':
                show_hashes_flag = true;
                break;
            case 'H':
                show_help(argv[0]);
                return EXIT_SUCCESS;
            default:
                show_help(argv[0]);
                return EXIT_FAILURE;
        }
    }

    if(show_hashes_flag) {
        show_hashes();
        return EXIT_SUCCESS;
    }

    if(optind >= argc) {
        fprintf(stderr, "\033[31m[!] Error: No target hash specified\033[0m\n");
        show_help(argv[0]);
        return EXIT_FAILURE;
    }

    target_hash = argv[optind];

    if(num_wordlist_files == 0) {
        fprintf(stderr, "\033[31m[!] Error: No wordlist specified\033[0m\n");
        show_help(argv[0]);
        return EXIT_FAILURE;
    }

    if(hash_type == NULL) {
        fprintf(stderr, "\033[31m[!] Error: No hash type specified\033[0m\n");
        show_help(argv[0]);
        return EXIT_FAILURE;
    }

    const HashAlgorithm *algorithm = NULL;
    for(size_t i = 0; i < num_algorithms; i++) {
        if(strcasecmp(hash_type, ALGORITHMS[i].name) == 0) {
            algorithm = &ALGORITHMS[i];
            break;
        }
    }

    if(algorithm == NULL) {
        fprintf(stderr, "\033[31m[!] Error: Unsupported hash algorithm '%s'\033[0m\n", hash_type);
        show_hashes();
        return EXIT_FAILURE;
    }

    if(!is_valid_hash(target_hash, algorithm)) {
        fprintf(stderr, "\033[31m[!] Error: Invalid %s hash format\033[0m\n", algorithm->name);
        return EXIT_FAILURE;
    }

    printf("\033[33m[-]\033[0m Target hash: %s (%s)\n", target_hash, algorithm->name);
    printf("\033[33m[-]\033[0m Using %d threads\n", num_threads);

    char *target_hash_lower = strdup(target_hash);
    for (char *p = target_hash_lower; *p; ++p) {
        *p = tolower(*p);
    }

    atomic_bool found = ATOMIC_VAR_INIT(false);
    char result[MAX_LINE_LENGTH] = {0};
    atomic_size_t total_tried = ATOMIC_VAR_INIT(0);
    time_t start_time = time(NULL);
    pthread_mutex_t result_mutex = PTHREAD_MUTEX_INITIALIZER;

    for(size_t i = 0; i < num_wordlist_files && !atomic_load(&found); i++) {
        if(!file_exists(wordlist_files[i])) {
            fprintf(stderr, "\033[31m[!] Error: Wordlist file '%s' not found\033[0m\n", wordlist_files[i]);
            continue;
        }

        int fd = open(wordlist_files[i], O_RDONLY);
        if (fd == -1) {
            fprintf(stderr, "\033[31m[!] Error: Could not open wordlist '%s'\033[0m\n", wordlist_files[i]);
            continue;
        }
        
        struct stat sb;
        if (fstat(fd, &sb) == -1) {
            close(fd);
            fprintf(stderr, "\033[31m[!] Error: Could not get file size for '%s'\033[0m\n", wordlist_files[i]);
            continue;
        }
        
        const char *file_data = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
        if (file_data == MAP_FAILED) {
            close(fd);
            fprintf(stderr, "\033[31m[!] Error: Could not mmap wordlist '%s'\033[0m\n", wordlist_files[i]);
            continue;
        }
        
        size_t total_words = count_lines_mmap(file_data, sb.st_size);
        printf("\033[36m[?]\033[0m Using wordlist: %s\n", wordlist_files[i]);
        printf("\033[33m[-]\033[0m Trying %zu words...\n", total_words);

        pthread_t threads[MAX_THREADS];
        ThreadData thread_data[MAX_THREADS];

        size_t chunk_size = sb.st_size / num_threads;
        for(int t = 0; t < num_threads; t++) {
            thread_data[t].data = file_data;
            thread_data[t].data_size = sb.st_size;
            thread_data[t].start_offset = t * chunk_size;
            thread_data[t].end_offset = (t == num_threads - 1) ? sb.st_size : (t + 1) * chunk_size;
            thread_data[t].algorithm = algorithm;
            thread_data[t].target_hash = target_hash_lower;
            thread_data[t].found = &found;
            thread_data[t].result = result;
            thread_data[t].result_mutex = &result_mutex;
            thread_data[t].total_tried = &total_tried;
            thread_data[t].total_words = total_words;
            thread_data[t].start_time = start_time;

            pthread_create(&threads[t], NULL, crack_thread, &thread_data[t]);
        }

        for(int t = 0; t < num_threads; t++) {
            pthread_join(threads[t], NULL);
        }

        munmap((void*)file_data, sb.st_size);
        close(fd);

        if(atomic_load(&found)) {
            time_t end_time = time(NULL);
            double elapsed = difftime(end_time, start_time);
            printf("\n\033[32m[!]\033[0m Found match: \033[32m%s\033[0m\n", result);
            printf("\033[33m[-]\033[0m Cracked in %.0f seconds (%.0f hashes/sec)\n", 
                  elapsed, atomic_load(&total_tried) / (elapsed ? elapsed : 1));
        } else {
            time_t end_time = time(NULL);
            double elapsed = difftime(end_time, start_time);
            printf("\033[31m[!]\033[0m No match found in this wordlist\n");
            printf("\033[33m[-]\033[0m Tried %zu hashes in %.0f seconds (%.0f hashes/sec)\n",
                  atomic_load(&total_tried), elapsed, atomic_load(&total_tried) / (elapsed ? elapsed : 1));
        }
    }

    free(target_hash_lower);
    for(size_t i = 0; i < num_wordlist_files; i++) {
        free(wordlist_files[i]);
    }
    free(wordlist_files);
    pthread_mutex_destroy(&result_mutex);

    return atomic_load(&found) ? EXIT_SUCCESS : EXIT_FAILURE;
}
