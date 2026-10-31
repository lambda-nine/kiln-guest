"""Execute the actual replacement's fallback on native Linux/aarch64."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]

@unittest.skipUnless(os.uname().sysname=='Linux' and os.uname().machine=='aarch64',
                     'native guest-kernel architecture required')
class ClearPageTests(unittest.TestCase):
    def test_actual_assembly_clears_one_page_without_overwriting_neighbors(self):
        with tempfile.TemporaryDirectory() as d:
            work=Path(d)
            for directory in ['linux','asm']: (work/directory).mkdir()
            (work/'linux/linkage.h').write_text('''
#define SYM_FUNC_START(name) .global name; .type name, %function; name:
#define SYM_FUNC_END(name) .size name, .-name
#define SYM_FUNC_ALIAS(alias, name) .global alias; .set alias, name
#define EXPORT_SYMBOL(name)
''')
            for name in ['linux/const.h','asm/assembler.h']:
                (work/name).write_text('')
            (work/'asm/page.h').write_text('#define PAGE_SIZE 4096\n')
            (work/'probe.c').write_text('''
#include <stdlib.h>
#include <string.h>
extern void clear_page(void *);
int main(void) {
    unsigned char *p=aligned_alloc(4096,3*4096);
    if (!p) return 1;
    for (unsigned value=1;value<256;value++) {
        memset(p,value,3*4096);
        clear_page(p+4096);
        for (int i=0;i<3*4096;i++)
            if (p[i] != (i>=4096 && i<8192 ? 0 : value)) return 2;
    }
    free(p); return 0;
}
''')
            # MOPS is absent on the measured target. Compile the complete
            # replacement file with its real ordinary-store fallback.
            subprocess.run(['gcc','-Wall','-Wextra','-Werror','-I',str(work),
                            str(ROOT/'src/kernel-clear-page.S'),str(work/'probe.c'),
                            '-o',str(work/'probe')],check=True,capture_output=True)
            subprocess.run([str(work/'probe')],check=True,capture_output=True)

if __name__=='__main__': unittest.main()
