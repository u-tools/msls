//
// Mimic stdio for more-style pagination
//
// Copyright (c) 2004-2018, U-Tools Software LLC
// Written by Alan Klietz
// Distributed under GNU General Public License version 2.
//

#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

struct more {
    char *ptr;
    int cnt;
    char *base;
    int err;
    int bufsiz;
    FILE *file;
    int istty; // 0=no, >0=yes, -1=dunno yet
    size_t nflushed; // total bytes flushed
};
typedef struct more MORE;

#define more_putc(c, m) (--(m)->cnt >= 0 \
    ? (0xff & (*(m)->ptr++ = (char)(c))) : _more_flushbuf((c),(m)))

#define more_putchar(c)  more_putc(c, stdmore)

// Note: puts() appends '\n' while fputs does not.
#define more_puts(s) \
    do { more_fputs(s, stdmore); more_putc('\n', stdmore); } while(0)

// Count of total bytes output
#define MORE_COUNT(m) (((m)->ptr - (m)->base) + (m)->nflushed)

extern struct more* stdmore; // stdout replacement
extern struct more* stdmore_err; // stderr replacement

extern int more_enable(int enable);
extern int _more_flushbuf(char ch, struct more *m);
extern int more_fflush(struct more *m);
extern int more_fputs(const char *s, struct more* m);
extern size_t more_fwrite(const char *s, int siz, int n, struct more* m);
extern int more_fprintf(struct more *, const char *fmt, ...);
extern int more_vfprintf(struct more *m, const char *fmt, va_list args);
extern int more_printf(const char *fmt, ...);

#ifdef __cplusplus
}
#endif

/*
vim:tabstop=4:shiftwidth=4:expandtab
*/
