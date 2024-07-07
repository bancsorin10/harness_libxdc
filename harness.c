#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <sys/stat.h>

struct loaded_file_s {
    uint64_t base_addr;
    uint64_t end_addr;
    uint64_t offset;
    void     *file_map;

    // needed for cleanup mostly
    uint64_t map_size;
    int      fd;
};

struct bin_map_s {
    struct loaded_file_s **loaded;

    uint64_t last_page;
    uint64_t last_addr;
};

static void read_map(int pid, char *map) {
    FILE *proc;
    char path[50];
    sprintf(path, "/proc/%d/maps", pid);
    proc = fopen(path, "r");
    if (!proc)
        printf("fopen failed\n");
    fread(map, 4096, 1, proc);
    fclose(proc);
}

static uint64_t get_map_len(char map[]) {
    uint64_t i;
    uint64_t len;

    i   = 0;
    len = 0;
    while (map[i]) {
        if (map[28+i] == 'x' && map[73+i] == '/') {
            ++len;
        }
        while (map[i] && map[i] != '\n') ++i;
        if (map[i])
            ++i;
    }

    return len;
}

static void *load_file(char path[], int *fd, uint64_t *size) {
    struct stat sb;
    int stat_res;
    void *file_map;

    *fd = open(path, O_RDONLY);
    if (*fd <= 0) {
        printf("couldn't open file\n");
        exit(0);
    }

    stat_res = fstat(*fd, &sb);
    if (stat_res < 0) {
        printf("stat failed\n");
        exit(0);
    }

    file_map = mmap(NULL, sb.st_size, PROT_READ, MAP_SHARED, *fd, 0);
    *size = sb.st_size;

    if (file_map == NULL) {
        printf("couldn't map file, panic\n");
        exit(0);
    }

    return file_map;
}

static void cache_map_init(
        char map[],
        struct bin_map_s **cache_map_ptr,
        uint64_t map_len) {

    uint64_t i;
    uint64_t j;
    struct bin_map_s *cache_map = *cache_map_ptr;
    char path[255];

    i = 0;
    j = 0;
    while (map[i]) {
        if (map[28+i] == 'x' && map[73+i] == '/') {
            if (cache_map->loaded[j] == NULL) {
                printf("loaded is null? panic\n");
                exit(0);
            }

            sscanf(map+i, "%lx", &(cache_map->loaded[j]->base_addr));
            sscanf(map+i+13, "%lx", &(cache_map->loaded[j]->end_addr));
            sscanf(map+i+30, "%lx", &(cache_map->loaded[j]->offset));
            sscanf(map+i+73, "%s", path);

            cache_map->loaded[j]->file_map =
                load_file(path,
                        &(cache_map->loaded[j]->fd),
                        &(cache_map->loaded[j]->map_size));

            ++j;
        }

        while (map[i] && map[i] != '\n') ++i;
        if (map[i])
            ++i;
    }
}

static struct bin_map_s *create_cache_map(char map[]) {
    
    uint64_t i;
    uint64_t map_len;
    struct bin_map_s *cache_map;

    map_len = get_map_len(map);

    // allocate the bin map
    cache_map = (struct bin_map_s *)malloc(sizeof(struct bin_map_s));
    if (cache_map == NULL) {
        printf("could not allocate map\n");
        return NULL;
    }
    cache_map->loaded = (struct loaded_file_s **)malloc
        (sizeof(struct loaded_file_s) * (map_len + 1));
    if (cache_map->loaded == NULL) {
        printf("could not allocate leaded\n");
        goto err_cleanup;
    }

    // safety stop
    cache_map->loaded[map_len] = NULL;

    i = 0;
    while (i < map_len) {
        cache_map->loaded[i] = (struct loaded_file_s *)malloc
            (sizeof(struct loaded_file_s));
        if (cache_map->loaded[i] == NULL) {
            printf("could not allocate loaded\n");
            goto err_cleanup;
        }
        ++i; 
    }

    cache_map_init(map, &cache_map, map_len);

    return cache_map;

err_cleanup:
    uint64_t j;

    if (cache_map->loaded) {
        j = 0;
        while (j < i) {
            if (cache_map->loaded[j]) {
                free(cache_map->loaded[j]);
            }
            ++j;
        }
        free(cache_map->loaded);
    }

    if (cache_map) {
        free(cache_map);
    }

    return NULL;
}

// prolly never used as a true harness besides testing
static void free_cache_map(struct bin_map_s *cache_map) {
    uint64_t i;

    if (cache_map == NULL) {
        return ;
    }

    if (cache_map->loaded == NULL) {
        free(cache_map);
        return;
    }

    i = 0;
    while (cache_map->loaded[i] != NULL) {
        munmap(cache_map->loaded[i]->file_map, cache_map->loaded[i]->map_size);
        close(cache_map->loaded[i]->fd);
        free(cache_map->loaded[i]);
        ++i;
    }

    free(cache_map->loaded);
    free(cache_map);
}

static void *fetch_cache_page(void *self_ptr, uint64_t page, bool *success) {
    struct bin_map_s *self = self_ptr;
    page &= 0xFFFFFFFFFFFFF000ULL;
    uint64_t addr;
    uint64_t i;

    if (page == self->last_addr) {
        return (void *)self->last_addr;
    }

    i = 0;
    while (self->loaded[i] != NULL) {
        if (page >= self->loaded[i]->base_addr &&
                page < self->loaded[i]->end_addr) {
            self->last_page = page;
            self->last_addr =
                ((uint64_t)self->loaded[i]->file_map) +
                (page - self->loaded[i]->base_addr + self->loaded[i]->offset);

            return (void *)self->last_addr;
        }
        ++i;
    }

    // should never be reached
    printf("fetching failed\n");
    return 0;
}

static void debug_print_cache_map(struct bin_map_s *cache_map) {
    uint64_t i;

    i = 0;
    while (cache_map->loaded[i]) {
        printf("original: 0x%lx - 0x%lx\n",
                cache_map->loaded[i]->base_addr,
                cache_map->loaded[i]->end_addr);
        printf("harness:  %p - 0x%lx\n",
                cache_map->loaded[i]->file_map,
                ((uint64_t)cache_map->loaded[i]->file_map) +
                cache_map->loaded[i]->map_size);

        ++i;
    }
}

static __attribute__((constructor)) void main(int ac, char **av) {

    char map[4096];
    uint64_t main_off = 0x1135;
    uint64_t base;
    uint64_t off;
    struct bin_map_s *cache_map;
    bool succ;

    read_map(getpid(), map);

    cache_map = create_cache_map(map);

    if (cache_map == NULL) {
        printf("cache_map creation failed\n");
        exit(0);
    }

    debug_print_cache_map(cache_map);
    
    int (*main_func)(int, char **) = ((int (*)(int, char **))(cache_map->loaded[0]->base_addr - cache_map->loaded[0]->offset + main_off));

    printf("main addr %p\n", main_func);
    printf("main page fetched %p\n", fetch_cache_page((void *)cache_map, (uint64_t)(void *)main_func, &succ));
    main_func(ac, av);
    exit(0);

    int i;

    // afl init
    // afl loop
    for (i = 0; i < 10; ++i) {
        printf("calling main from orig: ");
        main_func(ac, av);
    }
    free_cache_map(cache_map);
    exit(0);
}
