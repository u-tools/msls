/* prototypes for quote.c */

/* $Id: quote.h,v 1.1 2004/02/02 07:16:32 alank Exp $ */

#ifndef PARAMS
# if defined PROTOTYPES || (defined __STDC__ && __STDC__)
#  define PARAMS(Args) Args
# else
#  define PARAMS(Args) ()
# endif
#endif

char const *quote_n PARAMS ((int n, char const *name));
char const *quote PARAMS ((char const *name));
