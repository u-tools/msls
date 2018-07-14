/* Written by Paul Eggert <eggert@twinsun.com> */

/* $Id: quote.c,v 1.1 2004/02/02 07:16:32 alank Exp $ */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#if HAVE_STDDEF_H
# include <stddef.h>  /* For the definition of size_t on windows w/MSVC.  */
#endif
#include <sys/types.h>
#include <quotearg.h>
#include <quote.h>

/* Return an unambiguous printable representated, allocated in slot N,
   for NAME, suitable for diagnostics.  */
char const *
quote_n (int n, char const *name)
{
  return quotearg_n_style (n, locale_quoting_style, name);
}

/* Return an unambiguous printable representation of NAME, suitable
   for diagnostics.  */
char const *
quote (char const *name)
{
  return quote_n (0, name);
}
