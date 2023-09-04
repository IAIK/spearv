// See LICENSE for license details.

#ifndef _RISCV_COMMON_H
#define _RISCV_COMMON_H

#ifdef __GNUC__
# define   likely(x) __builtin_expect(x, 1)
# define unlikely(x) __builtin_expect(x, 0)
#else
# define   likely(x) (x)
# define unlikely(x) (x)
#endif

#define NOINLINE __attribute__ ((noinline))

/////////////////////////////// DEBUG Printing stuff
#define COLOR_RED     "\x1b[31m"
#define COLOR_GREEN   "\x1b[32m"
#define COLOR_YELLOW  "\x1b[33m"
#define COLOR_BLUE    "\x1b[34m"
#define COLOR_MAGENTA "\x1b[35m"
#define COLOR_CYAN    "\x1b[36m"
#define COLOR_RESET   "\x1b[0m"
#define COLOR_INFO    COLOR_CYAN

extern size_t debug_log_level;
//#define ERROR_FAIL2(MESSAGE, ...) do { if(debug_log_level >=  1) { fprintf(stderr, COLOR_RED    "%s:%d: " MESSAGE COLOR_RESET, __FILE__, __LINE__, ##__VA_ARGS__); if(errno){perror(NULL);} } exit(EXIT_FAILURE);} while (0)
#define ERROR_FAIL(MESSAGE, ...)  do { if(debug_log_level >=  1) { fprintf(stderr, COLOR_RED    "[SPIKE] %s: " MESSAGE COLOR_RESET, __func__, ##__VA_ARGS__); if(errno){perror(NULL);} } exit(EXIT_FAILURE);} while (0)
#define ERROR(MESSAGE, ...)       do { if(debug_log_level >=  2) { fprintf(stderr, COLOR_RED    "[SPIKE] %s: " MESSAGE COLOR_RESET, __func__, ##__VA_ARGS__); }} while (0)
#define WARNING(MESSAGE, ...)     do { if(debug_log_level >=  3) { fprintf(stderr, COLOR_YELLOW "[SPIKE] %s: " MESSAGE COLOR_RESET, __func__, ##__VA_ARGS__); }} while (0)
#define INFO(MESSAGE, ...)        do { if(debug_log_level >=  5) { fprintf(stderr, COLOR_INFO   "[SPIKE] %s: " MESSAGE COLOR_RESET, __func__, ##__VA_ARGS__); }} while (0)
#define INFO2(MESSAGE, ...)        do { if(debug_log_level >=  5) { fprintf(stderr, COLOR_INFO   MESSAGE COLOR_RESET, ##__VA_ARGS__); }} while (0)

//#define VERBOSE(MESSAGE, ...)     do { if(debug_log_level >=  8) { fprintf(stderr, COLOR_CYAN   "%s: " MESSAGE COLOR_RESET, __func__, ##__VA_ARGS__); }} while (0)
//#define DEBUG(MESSAGE, ...)       do { if(debug_log_level >= 10) { fprintf(stderr, COLOR_CYAN   "%s: " MESSAGE COLOR_RESET, __func__, ##__VA_ARGS__); }} while (0)

#endif
