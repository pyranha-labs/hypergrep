/*
 * Hyperscan library used to perform pattern matching against lines in text files.
 *
 * Primary use is through the hyperscan() function, which sends results to an external caller.
 * It can also be built as a standalone executable for manual testing.
 *
 * Build instructions:
 *     Standalone:
 *     gcc -o hyperscanner hyperscanner.c $(pkg-config --cflags --libs libhs libzstd zlib)
 *
 *     Shared library:
 *     gcc -c -Wall -Werror -fpic hyperscanner.c $(pkg-config --cflags --libs libhs libzstd zlib)
 *     gcc -shared -o libhyperscanner.so hyperscanner.o $(pkg-config --cflags --libs libhs libzstd zlib)
 *
 * Usage:
 *     ./hstest <pattern> <input file>
 */

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <hs.h>
// Use zstd_zlibwrapper.h instead of zlib.h, it has equivalents for all required gz* calls compatible with both types.
// If a non-ZSTD compatible build is required, replace with zlib.h and no additional changes are needed.
#include <zstd_zlibwrapper.h>

// Return codes for failures from hyperscanner.
typedef enum hyperscanner_ret {
    HYPERSCANNER_COMPILE_MEM = 1,
    HYPERSCANNER_COMPILE = 2,
    HYPERSCANNER_SCRATCH = 3,
    HYPERSCANNER_DB = 4,
    HYPERSCANNER_STATE_MEM = 5,
    HYPERSCANNER_GZ_OPEN = 6,
    HYPERSCANNER_SCAN = 7
} hyperscanner_ret_t;

/*
 * Callback function used by hyperscanner onEvent in order to send a result to an external caller.
 *
 * lineNumber: The index of the line matched within the file read by the hyperscanner.
 * matchId: The id of the pattern matched within the line.
 * line: Contents of the line that was matched.
 */
typedef void (*hs_event) (unsigned long long lineNumber, unsigned int matchId, char* line);

/*
 * Stateful information used to track additional information from Intel Hyperscan during callbacks.
 *
 * lineNumber: The index of the line matched.
 * line: Contents of the line that was matched.
 * callback: Function to call with simplified match information from Intel Hyperscan.
 */
typedef struct hyperscanner_state {
    unsigned long long lineNumber;
    char* line;
    hs_event callback;
} hyperscanner_state_t;

/*
 * Callback function used by Intel Hyperscan to pass-through match information to an external callback.
 *
 * id: The index of the pattern that matched the line.
 * start: The beginning position of the pattern matched within the line.
 * end: The last position of the pattern matched within the line.
 * flags: What flags were set on this pattern in order to match. i.e. HS_FLAG_DOTALL
 * ctx: Pointer to any data type passed through for reference by hs_scan(). i.e. line as (char*), struct, etc.
 */
static int hs_callback(unsigned int id, unsigned long long start, unsigned long long end, unsigned int flags, void *ctx) {
    hyperscanner_state_t* state = (hyperscanner_state_t*) ctx;
    state->callback(state->lineNumber, id, state->line);
    return 0;
}

/*
 * Dummy callback function to allow testing library through main() by printing the matched lines.
 */
static void event_handler(unsigned long long lineNumber, unsigned int matchId, char* line) {
    // Print off a line similar to grep -n, where it starts with the line number.
    printf("%llu:%s", lineNumber, line);
}

/*
 * Initialize an Intel Hyperscan database from multiple regex patterns.
 *
 * db: Location of the Intel Hyperscan database in memory. It will be initialized in-place.
 * expressions: Regex patterns to initialize into the database.
 * expression_flags: Flags to set on each regex pattern in order to match. i.e. HS_FLAG_DOTALL
 *     Flags in hyperscan use a bitwise OR operator to combine flags. e.g. HS_FLAG_DOTALL | HS_FLAG_SINGLEMATCH == 10
 * elements: Size the pattern array.
 */
static int init_hs_db(hs_database_t** db, const char* const* expressions, const unsigned int* expression_flags, int elements) {
    int ret = 0;

    // Create an id and flag for every expression. These must be in the same order as the expression they apply to.
    hs_compile_error_t* err = NULL;
    unsigned int* ids = (unsigned int*) malloc(sizeof(unsigned int) * elements);
    unsigned int* flags = (unsigned int*) malloc(sizeof(unsigned int) * elements);
    if (!ids || !flags) {
        ret = HYPERSCANNER_COMPILE_MEM;
        goto cleanup;
    }

    for (int id = 0; id < elements; id++) {
        ids[id] = id;
        // Hyperscan flags: https://intel.github.io/hyperscan/dev-reference/api_files.html
        flags[id] = expression_flags[id];
    }

    if (hs_compile_multi(expressions, flags, ids, elements, HS_MODE_BLOCK, NULL, db, &err) != HS_SUCCESS) {
        ret = HYPERSCANNER_COMPILE;
    }

cleanup:
    // Ensure the error, ids, and flags are freed before exiting regardless of compilation status.
    hs_free_compile_error(err);
    free(flags);
    free(ids);
    return ret;
}

/*
 * Scan a GZIP file using Intel Hyperscan.
 *
 * fileName: Location of a local file that can be read line by line.
 * state: Stateful information used to track additional details from Intel Hyperscan during callbacks.
 * db: A compiled Hyperscan pattern database.
 * scratch: A per-thread Hyperscan scratch space allocated for this database.
 * bufSize: How large of a char buffer to use while reading in strings. Reads up to first newline or len - 1.
 */
int hyperscan_gz(char* fileName, hyperscanner_state_t* state, hs_database_t* db, hs_scratch_t* scratch, int bufSize) {
    int ret = 0;

    // To avoid manual line scanning, use zlib gz* functions to open files and read into buffer.
    // For details on manually reading gzips without gzopen: https://zlib.net/zlib_how.html
    gzFile inputFile = gzopen(fileName, "rb");
    if (inputFile == Z_NULL) {
        // File could not be opened for reading due to permissions, or bad file type.
        ret = HYPERSCANNER_GZ_OPEN;
    }

    char *buf = malloc(sizeof(char) * bufSize);
    while (1) {
        state->line = gzgets(inputFile, buf, bufSize);
        if (state->line == Z_NULL) {
            // EOF or unreadable file.
            break;
        }

        // Hyperscan the buffer up to the end of the current line. ZLIB will read up to a newline or max buffer length.
        if (hs_scan(db, state->line, strlen(state->line), 0, scratch, hs_callback, state) != HS_SUCCESS) {
            fprintf(stderr, "ERROR: Unable to scan buffer. Exiting.\n");
            ret = HYPERSCANNER_SCAN;
            break;
        }
        state->lineNumber++;
    }
    gzclose(inputFile);

    free(buf);
    return ret;
}

/*
 * Scan a file using Intel Hyperscan for high performance using multiple regexes.
 *
 * fileName: Location of a local file that can be read line by line.
 * patterns: Regular expressions to be scanned against every line.
 * pattern_flags: Flags to set on each pattern in order to match. i.e. HS_FLAG_DOTALL
 *     Flags in hyperscan use a bitwise OR operator to combine flags. e.g. HS_FLAG_DOTALL | HS_FLAG_SINGLEMATCH == 10
 * elements: Size the pattern array.
 * onEvent: Function to call with simplified match information from Intel Hyperscan.
 * bufSize: How large of a char buffer to use while reading in strings. Reads up to first newline or len - 1.
 */
int hyperscan(char* fileName, const char* const* patterns, const unsigned int* pattern_flags, const unsigned int elements, hs_event onEvent, const int bufSize) {
    int ret = 0;

    // Initialize the Hyperscan database, scratch, and state. If any cannot be created, skip processing.
    hyperscanner_state_t* state = (hyperscanner_state_t*) malloc(sizeof(hyperscanner_state_t));
    if (!state) {
        ret = HYPERSCANNER_STATE_MEM;
        goto cleanup;
    }
    state->lineNumber = 0;
    state->callback = onEvent;

    hs_database_t* db = NULL;
    hs_scratch_t* scratch = NULL;
    if (init_hs_db(&db, patterns, pattern_flags, elements) != 0) {
        fprintf(stderr, "ERROR: Unable to create database. Exiting.\n");
        ret = HYPERSCANNER_DB;
        goto cleanup;
    }
    if (hs_alloc_scratch(db, &scratch) != HS_SUCCESS) {
        fprintf(stderr, "ERROR: Unable to allocate scratch space. Exiting.\n");
        ret = HYPERSCANNER_SCRATCH;
        goto cleanup;
    }

    // Route scan based on file type to isolate dynamic buffer allocation scope.
    ret = hyperscan_gz(fileName, state, db, scratch, bufSize);

cleanup:
    // Ensure the scratch, database, and state are freed before exiting.
    hs_free_scratch(scratch);
    hs_free_database(db);
    free(state);
    return ret;
}

/*
 * Simple function to test reading a file and printing matches when run as a standalone tool.
 *
 * argc: Number of arguments passed from the command line.
 * argv: Arguments passed from the command line.
 */
int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <input file> <patterns...>\n", argv[0]);
        return -1;
    }

    char* inputFile = argv[1];
    int elements = argc - 2;
    const char* patterns[elements];
    unsigned int pattern_flags[elements];
    for (int i = 2; i < argc; i++) {
        patterns[i - 2] = argv[i];
        // HS_FLAG_DOTALL for performance.
        // HS_FLAG_MULTILINE to match ^ and $ against newlines.
        // HS_FLAG_SINGLEMATCH to stop after first callback for a pattern.
        pattern_flags[i - 2] = HS_FLAG_DOTALL | HS_FLAG_MULTILINE | HS_FLAG_SINGLEMATCH;
    }

    return hyperscan(inputFile, patterns, pattern_flags, elements, event_handler, 65535);
}
