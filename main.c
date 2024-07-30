#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <errno.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <openssl/evp.h>
#include <limits.h>

#define CHUNK_SIZE 4096
#define MAX_PATH_LENGTH 1024
#define MAX_CHECKSUM_LENGTH 65
#define MAX_JOBS 1024

// Define a structure for expected items
struct ExpectedItem {
    char *path;
    mode_t expected_mode;
    char *expected_checksum;
};

// Hash algorithm options
typedef enum {
    HASH_MD5,
    HASH_SHA1,
    HASH_SHA256
} HashAlgorithm;

struct ExpectedItem *expected_items = NULL;
int num_expected_items = 0;
HashAlgorithm hash_algorithm = HASH_SHA256; // Default

// Global file pointer for report
FILE *report_file;

// Function to calculate the checksum of a file
void calculate_checksum(const char *path, char output[MAX_CHECKSUM_LENGTH]) {
    FILE *file = fopen(path, "rb");
    if (!file) {
        perror("fopen");
        strcpy(output, "error");
        return;
    }

    unsigned char buffer[CHUNK_SIZE];
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();

    const EVP_MD *md = NULL;
    switch (hash_algorithm) {
        case HASH_MD5:
            md = EVP_md5();
            break;
        case HASH_SHA1:
            md = EVP_sha1();
            break;
        case HASH_SHA256:
            md = EVP_sha256();
            break;
    }

    EVP_DigestInit_ex(mdctx, md, NULL);

    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, CHUNK_SIZE, file))) {
        EVP_DigestUpdate(mdctx, buffer, bytes_read);
    }

    EVP_DigestFinal_ex(mdctx, hash, &hash_len);
    fclose(file);
    EVP_MD_CTX_free(mdctx);

    for (unsigned int i = 0; i < hash_len; i++) {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
    output[hash_len * 2] = '\0'; // Null-terminate the string
}

// Function to check existence, permissions, and checksum
void check_existence_permissions_and_checksum(const char *path, mode_t expected_mode, const char *expected_checksum) {
    struct stat statbuf;
    char actual_permissions_str[11];
    char expected_permissions_str[11];
    char actual_checksum[MAX_CHECKSUM_LENGTH];

    // Check file existence
    if (stat(path, &statbuf) == -1) {
        if (errno == ENOENT) {
            fprintf(report_file, "Missing: %s\n", path);
        } else {
            fprintf(report_file, "Error accessing %s: %s\n", path, strerror(errno));
        }
        // Format expected permissions
        snprintf(expected_permissions_str, sizeof(expected_permissions_str), "%o", expected_mode);
        fprintf(report_file, "Actual Permissions: N/A\n");
        fprintf(report_file, "Expected Permissions: %s\n", expected_permissions_str);
        fprintf(report_file, "Expected Checksum: %s\n", expected_checksum ? expected_checksum : "none");
    } else {
        // Format actual permissions
        snprintf(actual_permissions_str, sizeof(actual_permissions_str), "%o", statbuf.st_mode & 0777);
        // Format expected permissions
        snprintf(expected_permissions_str, sizeof(expected_permissions_str), "%o", expected_mode);

        fprintf(report_file, "Path: %s\n", path);
        fprintf(report_file, "Actual Permissions: %s\n", actual_permissions_str);
        fprintf(report_file, "Expected Permissions: %s\n", expected_permissions_str);

        // Check permissions
        if ((statbuf.st_mode & 0777) != expected_mode) {
            fprintf(report_file, "Permission mismatch: Expected: %o, Actual: %o\n",
                    expected_mode, statbuf.st_mode & 0777);
        } else {
            fprintf(report_file, "Permissions are correct\n");
        }

        // Check checksum if expected_checksum is not NULL
        if (expected_checksum && S_ISREG(statbuf.st_mode)) {
            calculate_checksum(path, actual_checksum);

            fprintf(report_file, "Actual Checksum: %s\n", actual_checksum);
            fprintf(report_file, "Expected Checksum: %s\n", expected_checksum);

            if (strcmp(actual_checksum, expected_checksum) != 0) {
                fprintf(report_file, "Checksum mismatch\n");
            } else {
                fprintf(report_file, "Checksum is correct\n");
            }
        } else {
            fprintf(report_file, "Checksum not applicable\n");
        }
    }
}

// Function to get user input for expected items and hash algorithm
void get_user_input() {
    int algo_choice;
    printf("Choose hash algorithm:\n1. MD5\n2. SHA-1\n3. SHA-256\n");
    if (scanf("%d", &algo_choice) != 1 || algo_choice < 1 || algo_choice > 3) {
        fprintf(stderr, "Invalid choice.\n");
        exit(1);
    }

    hash_algorithm = (HashAlgorithm)(algo_choice - 1);

    printf("Enter the number of files/directories to check: ");
    if (scanf("%d", &num_expected_items) != 1 || num_expected_items <= 0) {
        fprintf(stderr, "Invalid number.\n");
        exit(1);
    }

    expected_items = malloc(num_expected_items * sizeof(struct ExpectedItem));
    if (!expected_items) {
        perror("malloc");
        exit(1);
    }

    for (int i = 0; i < num_expected_items; ++i) {
        char path[MAX_PATH_LENGTH];
        int mode;
        char checksum[MAX_CHECKSUM_LENGTH];

        printf("Enter path for item %d: ", i + 1);
        scanf("%s", path);

        printf("Enter expected permissions (e.g., 644 for rw-r--r--): ");
        if (scanf("%o", &mode) != 1) {
            fprintf(stderr, "Invalid permissions.\n");
            exit(1);
        }

        printf("Enter expected checksum (or 'none' if not applicable): ");
        scanf("%s", checksum);

        expected_items[i].path = strdup(path);
        expected_items[i].expected_mode = (mode_t)mode;
        if (strcmp(checksum, "none") == 0) {
            expected_items[i].expected_checksum = NULL;
        } else {
            expected_items[i].expected_checksum = strdup(checksum);
        }
    }
}

// Function to determine the number of CPU cores
int get_num_cpu_cores() {
    return sysconf(_SC_NPROCESSORS_ONLN);
}

// Function to execute checks with a job queue
void process_jobs() {
    pid_t pids[MAX_JOBS];
    int num_jobs = 0;
    int max_procs = get_num_cpu_cores();
    int job_index = 0;

    while (job_index < num_expected_items || num_jobs > 0) {
        // Fork new processes if there are still jobs and available slots
        while (num_jobs < max_procs && job_index < num_expected_items) {
            pids[num_jobs] = fork();
            if (pids[num_jobs] == 0) {
                // Child process
                check_existence_permissions_and_checksum(expected_items[job_index].path, expected_items[job_index].expected_mode, expected_items[job_index].expected_checksum);
                exit(0);
            } else if (pids[num_jobs] > 0) {
                // Parent process
                num_jobs++;
                job_index++;
            } else {
                perror("fork");
                exit(1);
            }
        }

        // Wait for at least one child process to finish
        if (num_jobs > 0) {
            wait(NULL);
            num_jobs--;
        }
    }
}

int main() {
    // Open report file
    report_file = fopen("report.txt", "w");
    if (!report_file) {
        perror("fopen");
        return 1;
    }

    // Get user input
    get_user_input();

    // Process jobs with parallelism optimization
    process_jobs();

    fprintf(report_file, "File and directory check completed.\n");
    fclose(report_file); // Close report file

    // Free allocated memory
    for (int i = 0; i < num_expected_items; i++) {
        free(expected_items[i].path);
        if (expected_items[i].expected_checksum) {
            free(expected_items[i].expected_checksum);
        }
    }
    free(expected_items);

    printf("File and directory check completed. See report.txt for details.\n");

    return 0;
}