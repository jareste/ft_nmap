#ifndef FT_MALLOC_H
#define FT_MALLOC_H

#include <stdlib.h>

#ifdef NDEBUG
    #define ft_assert(expr, message) \
        if (!(expr)) { \
            fprintf(stderr, "Assertion failed: %s\nFile: %s, Line: %d\n", message, __FILE__, __LINE__); \
            abort(); \
        }
#else
    #define ft_assert(expr, message) \
        if (!(expr)) { \
            fprintf(stderr, "Assertion failed: %s\nFile: %s, Line: %d\n", message, __FILE__, __LINE__); \
            exit(EXIT_FAILURE); \
        }
#endif

void* ft_malloc(size_t size);
void* ft_realloc(void *ptr, size_t size);
char* ft_strdup(const char *s);

#define malloc(x) ft_malloc(x)
#define realloc(x, y) ft_realloc(x, y)
#define strdup(x) ft_strdup(x)

#endif