/**
 * Santhosh Chandrasekaran
 * Copyright (C), 2023
 * University of California, Irvine
 *
 * CS 238P - Operating Systems
 * scm.c
 */

#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include "scm.h"

/**
 * Needs:
 *   fstat()
 *   S_ISREG()
 *   open()
 *   close()
 *   sbrk()
 *   mmap()
 *   munmap()
 *   msync()
 */

/* research the above Needed API and design accordingly */

#define VIRT_ADDR 0x600000000000

struct scm
{
    int fd;
    size_t utilized;
    size_t capacity;
    void *addr;
};

struct scm *file_size(const char *pathname)
{
    struct stat st;
    int fd;
    struct scm *scm;

    assert(pathname);

    if ((fd = open(pathname, O_RDWR)) == -1)
    {
        return NULL;
    }

    if (fstat(fd, &st) == -1)
    {
        close(fd);
        return NULL;
    }

    if (!S_ISREG(st.st_mode))
    {
        close(fd);
        return NULL;
    }

    if (!(scm = malloc(sizeof(struct scm))))
    {
        return NULL;
    }

    memset(scm, 0, sizeof(struct scm));

    scm->fd = fd;
    scm->utilized = 0;
    scm->capacity = st.st_size;

    return scm;
}

struct scm *scm_open(const char *pathname, int truncate)
{
    struct scm *scm = file_size(pathname);
    if (!scm)
    {
        return NULL;
    }

    if (sbrk(scm->capacity) == (void *)-1)
    {
        close(scm->fd);
        free(scm);
        return NULL;
    }

    if ((scm->addr = mmap((void *)VIRT_ADDR, scm->capacity, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_SHARED,
                          scm->fd, 0)) == MAP_FAILED)
    {
        close(scm->fd);
        free(scm);
        return NULL;
    }

    if (truncate)
    {
        if (ftruncate(scm->fd, scm->capacity) == -1)
        {
            close(scm->fd);
            free(scm);
            return NULL;
        }
        scm->utilized = 0;
    }
    else
    {
        scm->utilized = (size_t) * (size_t *)scm->addr;
        /* printf("scm->utilized: %lu\n", scm->utilized); */
    }
    scm->addr = (char *)scm->addr + sizeof(size_t);
    /* printf("scm->addr after: %p\n", scm->addr); */

    return scm;
}

void scm_close(struct scm *scm)
{
    if (scm)
    {
        /* printf("scm->addr: %p\n", scm->addr);
        printf("scm->utilized: %lu\n", scm->utilized); */
        msync((char *)VIRT_ADDR, scm->capacity, MS_SYNC);
        munmap((char *)VIRT_ADDR, scm->capacity);
        close(scm->fd);
        memset(scm, 0, sizeof(struct scm));
    }
    free(scm);
}

void *scm_malloc(struct scm *scm, size_t n)
{
    /*     Get the start address */
    void *startAddress = (char *)scm->addr;
    void *endAddress = (char *)scm->addr - sizeof(size_t) + scm->capacity;
    void *currentAddress = startAddress;
    short *isAddressFree;
    void *utilizedMemoryLoc; 
    size_t *sizeMemoryLocation;
    while (currentAddress < endAddress)
    {
        /*         Check if the current memory is free */
        isAddressFree = (short *)currentAddress;
        if (*isAddressFree)
        {
            /* Move the memory by the amount of memory occupied */
            sizeMemoryLocation = (size_t *)((char *)isAddressFree + sizeof(short));
            currentAddress = (char *)currentAddress + *sizeMemoryLocation;
            continue;
        }
        else
        {
            /*             If current memory is free get the memory capacity it can allocate */
            sizeMemoryLocation = (size_t *)((char *)isAddressFree + sizeof(short));
            if (!*sizeMemoryLocation)
            {
                *isAddressFree = 1;
                /* Update the utilized */
                scm->utilized += n + sizeof(short) + sizeof(size_t);
                utilizedMemoryLoc = (char *)scm->addr - sizeof(size_t);
                *(size_t *)utilizedMemoryLoc = scm->utilized;
                if (*sizeMemoryLocation == 0)
                    *sizeMemoryLocation = n + sizeof(short) + sizeof(size_t);
                return (char *)currentAddress + sizeof(short) + sizeof(size_t);
            }
            else
            {
                /* Move the memory by the amount of memory occupied */
                currentAddress = (char *)currentAddress + *sizeMemoryLocation;
                continue;
            }
        }
    }
    return NULL;
}

char *scm_strdup(struct scm *scm, const char *s)
{
    size_t n = strlen(s) + 1;
    char *p = scm_malloc(scm, n);
    if (!p)
    {
        return NULL;
    }
    memcpy(p, s, n);
    return p;
}

void scm_free(struct scm *scm, void *p)
{
    size_t size = *(size_t *)((char *)p - sizeof(size_t));
    *(short *)((char *)p - sizeof(short) - sizeof(size_t)) = 0;
    scm->utilized -= size;
    *(size_t *)((char *)scm->addr - sizeof(size_t)) = scm->utilized;
    /* p = (char *) scm->addr + scm->utilized; */
}

size_t scm_utilized(const struct scm *scm)
{
    return scm->utilized;
}

size_t scm_capacity(const struct scm *scm)
{
    return scm->capacity;
}

void *scm_mbase(struct scm *scm)
{
    return (char *)scm->addr + sizeof(short) + sizeof(size_t);
}