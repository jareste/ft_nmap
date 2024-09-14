#include <ft_malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#undef malloc
#undef realloc

void* ft_malloc(size_t size)
{
    void *ptr = malloc(size);
    ft_assert(ptr != NULL, "malloc failed");
    return ptr;
}

void* ft_realloc(void *ptr, size_t size)
{
    void* new_ptr = realloc(ptr, size);
    ft_assert(new_ptr != NULL, "realloc failed");
    return new_ptr;
}

char *ft_strdup(const char *s)
{
    size_t len = strlen(s);
    char *new_s = ft_malloc(len + 1);
    strcpy(new_s, s);
    new_s[len] = '\0';
    return new_s;
}