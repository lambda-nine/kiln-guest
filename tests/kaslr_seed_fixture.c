#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define __init
#define __initconst
typedef uint64_t u64;
typedef uint64_t fdt64_t;
struct tree { _Alignas(8) unsigned char kaslr[8], rng[64]; int klen, rlen; };
static void *fdt_getprop_w(void *fdt, int node, const char *name, int *len) {
    (void)node; struct tree *t=fdt;
    if (!strcmp(name,"kaslr-seed")) { *len=t->klen; return t->klen < 0 ? NULL : t->kaslr; }
    *len=t->rlen; return t->rlen < 0 ? NULL : t->rng;
}
static u64 fdt64_to_cpu(fdt64_t value) {
    const unsigned char *p=(const unsigned char *)&value; u64 result=0;
    for (int i=0;i<8;i++) result=(result<<8)|p[i];
    return result;
}
/* KERNEL_FUNCTION */
int main(void) {
    struct tree t={.klen=8,.rlen=64};
    memset(t.kaslr,0x13,8); memset(t.rng,0x45,64);
    if (get_kaslr_seed(&t,0) != UINT64_C(0x1313131313131313)) return 1;
    for (int i=0;i<8;i++) if (t.kaslr[i]) return 2;
    for (int i=0;i<64;i++) if (t.rng[i] != 0x45) return 3;
    t.klen=-1; for (int i=0;i<64;i++) t.rng[i]=(unsigned char)(i+1);
    if (get_kaslr_seed(&t,0) != UINT64_C(0x0102030405060708)) return 4;
    for (int i=0;i<8;i++) if (t.rng[i]) return 5;
    for (int i=8;i<64;i++) if (t.rng[i] != i+1) return 6;
    for (int size=0;size<=65;size++) {
        if (size==64) continue;
        t.rlen=size; memset(t.rng,0x77,64);
        if (get_kaslr_seed(&t,0) != 0) return 7;
        for (int i=0;i<64;i++) if (t.rng[i] != 0x77) return 8;
    }
    t.rlen=64; memset(t.rng,0x77,64);
    if (get_kaslr_seed(&t,-1) != 0) return 9;
    for (int i=0;i<64;i++) if (t.rng[i] != 0x77) return 10;
    puts("KASLR seed: standard priority, exact-length fallback, consumed bytes erased, 56 bytes preserved, invalid/missing node rejected");
    return 0;
}
