/* Fixed test-mode diagnostic, never a command execution interface. */
static long long probe_ns(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) die("probe clock");
    return (long long)now.tv_sec * 1000000000LL + now.tv_nsec;
}
static void zero_probe(void) {
    const size_t bytes = 1024 * 1024;
    unsigned char *p = aligned_alloc(4096, bytes);
    if (!p) die("zero probe allocation");
    memset(p, 0xa5, bytes);
    unsigned long dczid;
    __asm__ volatile("mrs %0, dczid_el0" : "=r"(dczid));
    long long start = probe_ns();
    for (int i = 0; i < 4096; i++)
        __asm__ volatile("mrs %0, dczid_el0" : "=r"(dczid));
    printf("KG_ZERO dczid=%lu reads=4096 ns=%lld\n", dczid, probe_ns()-start);
    if (!(dczid & 16)) {
        size_t stride = 4UL << (dczid & 15);
        start = probe_ns();
        for (size_t i = 0; i < bytes; i += stride)
            __asm__ volatile("dc zva, %0" :: "r"(p+i) : "memory");
        printf("KG_ZERO method=zva bytes=%zu ns=%lld\n", bytes, probe_ns()-start);
        for (size_t i = 0; i < bytes; i++)
            if (p[i]) die("zva probe failed");
    }
    memset(p, 0xa5, bytes);
    start = probe_ns();
    for (size_t i = 0; i < bytes; i += 64)
        __asm__ volatile("stnp xzr, xzr, [%0]\n"
                         "stnp xzr, xzr, [%0, #16]\n"
                         "stnp xzr, xzr, [%0, #32]\n"
                         "stnp xzr, xzr, [%0, #48]" :: "r"(p+i) : "memory");
    printf("KG_ZERO method=stnp bytes=%zu ns=%lld\n", bytes, probe_ns()-start);
    for (size_t i = 0; i < bytes; i++)
        if (p[i]) die("store probe failed");
    free(p);
}
