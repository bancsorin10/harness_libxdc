#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <libxdc.h>

#define PAGE_SIZE 0x1000

#define N 3
#define DATA_SIZE (1+(1<<N)) * PAGE_SIZE
#define AUX_SIZE  (1<<N) * PAGE_SIZE

#define BITMAP_SIZE 0x10000

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

static inline uint64_t rdtsc(void)
{
    uint32_t low, high;
    asm volatile("rdtsc":"=a"(low),"=d"(high));
    return ((uint64_t)high << 32) | low;
}

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
        struct bin_map_s **cache_map_ptr) {

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

    cache_map_init(map, &cache_map);

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
    uint64_t i;

    *success = true;
    // printf("hello page 0x%lx\n", page);

    if (page == self->last_page) {
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
    // printf("fetching failed\n");
    *success = false;
    return NULL;
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

// get code of the dynamic PMU provided by the intel_pt driver
static uint32_t get_intelpt_type() {
    int fd;
    char type[2];

    fd = open("/sys/bus/event_source/devices/intel_pt/type", O_RDONLY);
    read(fd, type, 2);
    close(fd);
    return (uint32_t)((type[0]-'0')*10 + type[1]-'0');
}

static int open_perf_event(int pid) {
    int fd;
    struct perf_event_attr attr;

    memset(&attr, 0, sizeof(attr));

    // read type from `/sys/bus/event_source/devices/intel_pt/type`
    // dynamic PMU for intel pt
    attr.type           = get_intelpt_type();
    attr.size           = sizeof(attr);
    attr.disabled       = 1;
    attr.exclude_kernel = 1;
    attr.exclude_hv     = 1;
    attr.exclude_idle   = 1;

    // attr.inherit        = 1;
    // attr.exclude_guest  = 1;
    // attr.sample_id_all  = 1;
    // attr.sample_period  = 1;

    // stolen with
    // `perf --debug verbose=2 record -e intel_pt/cyc=0,tsc=0,mtc=0,noretcomp=1/u ./hello`
    attr.config = 0x300e801;

    fd = syscall(SYS_perf_event_open, &attr, pid, -1, -1, 0);
    if (fd == -1) {
        printf("event open failed\n");
        exit(0);
    }

    return fd;
}

static void perf_allocate_buffers(
        int perf_fd,
        void **data_ptr,
        void **aux_ptr) {

    struct perf_event_mmap_page *header;
    void *base;
    void *aux;

    base = mmap(NULL, DATA_SIZE, PROT_WRITE, MAP_SHARED, perf_fd, 0);
    if (base == MAP_FAILED) {
        printf("base mmap failed\n");
        exit(0);
    }

    header = base;

    header->aux_offset = header->data_offset + header->data_size;
    header->aux_size    = AUX_SIZE;

    aux = mmap(NULL, header->aux_size, PROT_WRITE, MAP_SHARED, perf_fd,
               header->aux_offset);
    if (aux == MAP_FAILED) {
        printf("aux mmap failed\n");
        exit(0);
    }

    *data_ptr = base;
    *aux_ptr  = aux;
}

static void *load_bitmap(int *bitmap_fd) {
    // bitmap is loaded from a shared memory region / a file
    // the file name should be in an environment variable at least for
    // afl++
    // as a demo create a file with
    // `dd if=/dev/zero of=test_bitmap bs=1 count=$((0x10000))`

    int fd;
    void *bitmap;

    fd = open("test_bitmap", O_RDWR);
    if (fd <= 0) {
        printf("failed reading the bitmap\n");
        exit(0);
    }

    // int stat_res;
    // struct stat sb;
    // stat_res = fstat(fd, &sb);
    // if (stat_res < 0) {
    //     printf("stat failed in bitmap\n");
    //     exit(0);
    // }
    //
    // bitmap = mmap(NULL, sb.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

    // size of file is known
    bitmap = mmap(
            NULL,
            BITMAP_SIZE,
            PROT_READ | PROT_WRITE,
            MAP_SHARED,
            fd,
            0);

    *bitmap_fd = fd;

    return bitmap;
}

static void debug_log_aux(void *aux, uint64_t size) {
    int fd;

    fd = open("aux_log", O_WRONLY | O_CREAT, 0666);
    write(fd, aux, size);
    close(fd);
}

static uint64_t get_aux_size(void *data_ptr) {
    uint8_t *data;

    data = (uint8_t *)data_ptr;
    data += ((struct perf_event_mmap_page *)data)->data_offset;
    struct perf_event_header *h;

    while ((h = (struct perf_event_header *)data)->type != 0) {
        if (h->type == PERF_RECORD_AUX) {
            return *(uint64_t *)
                (data + sizeof(struct perf_event_header) + 8);
        }
        data += h->size;
    }
    return 0;
}

static __attribute__((constructor)) void main(int ac, char **av) {

    char map[4096];
    uint64_t main_off = 0x1135;
    struct bin_map_s *cache_map;

    read_map(getpid(), map);
    // printf("%s\n", map);

    cache_map = create_cache_map(map);

    if (cache_map == NULL) {
        printf("cache_map creation failed\n");
        exit(0);
    }

    // debug_print_cache_map(cache_map);
    
    // declare the main function
    int (*main_func)(int, char **) = ((int (*)(int, char **))(cache_map->loaded[0]->base_addr - cache_map->loaded[0]->offset + main_off));

    // setup intel_pt perf
    int perf_fd;
    void *data;
    void *aux;

    
    // setup decoding
    decoder_result_t ret;
    libxdc_t         *decoder;

    uint64_t filter[4][2] = {0}; // cr3 filters not supported by perf?
    uint8_t  *trace;
    void     *bitmap;
    int      bitmap_fd;


    // we don't really care we kinda mapped everything
    // there should be no problems
    filter[0][0] = 0x1;
    filter[0][1] = 0xffffffffffffffff;

    bitmap = load_bitmap(&bitmap_fd);

    decoder = libxdc_init(
            filter,
            &fetch_cache_page,
            cache_map,
            bitmap,
            BITMAP_SIZE);

    int i;
    for (i = 0; i < 50; ++i) {
        uint64_t elapsed = rdtsc();
        // reset bitmap
        // memset(bitmap, 0x00, BITMAP_SIZE);
        perf_fd = open_perf_event(getpid());
        // can't reset and zero the buffers so ill just free and reloc
        perf_allocate_buffers(perf_fd, &data, &aux);

        // enable intel_pt
        ioctl(perf_fd, PERF_EVENT_IOC_RESET, 0);
        ioctl(perf_fd, PERF_EVENT_IOC_ENABLE, 0);

        // run main
        main_func(ac, av);

        // disable intel_pt
        ioctl(perf_fd, PERF_EVENT_IOC_DISABLE, 0);

        uint64_t curr_aux_size;
        curr_aux_size = get_aux_size(data);
        // can't write to trace
        // ((uint8_t *)aux)[AUX_SIZE-1] = 0x55;
        trace = (uint8_t *)malloc(curr_aux_size + 1);
        memcpy(trace, aux, curr_aux_size);
        trace[curr_aux_size] = 0x55;
        // debug_log_aux(aux, AUX_SIZE);
        // debug_log_aux(trace, curr_aux_size+1);

        // printf("aux %p-%p size 0x%lx\n", trace, trace+curr_aux_size, curr_aux_size);

        ret = libxdc_decode(decoder, trace, curr_aux_size);
        if (ret) {
            printf("decoding failed %d\n", ret);
        }
        // free(trace);

        // free buffers
        if (data) {
            munmap(data, DATA_SIZE);
        }

        if (aux) {
            munmap(aux, AUX_SIZE);
        }

        close(perf_fd);

        elapsed = rdtsc() - elapsed;
        printf("elapsed ticks %ld\n", elapsed);

    }


cleanup:
    if (trace) {
        free(trace);
    }

    if (bitmap) {
        munmap(bitmap, BITMAP_SIZE);
        close(bitmap_fd);
    }

    //close(perf_fd);

    free_cache_map(cache_map);

    exit(0);
}
