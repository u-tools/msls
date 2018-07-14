#ifndef FILEMODE_H_

/* $Id: filemode.h,v 1.1 2004/02/02 07:16:24 alank Exp $ */

#ifdef __cplusplus // AEK
extern "C" {
#endif

# if HAVE_CONFIG_H
#  include <config.h>
# endif

# include <sys/types.h>

# ifndef PARAMS
#  if defined PROTOTYPES || (defined __STDC__ && __STDC__)
#   define PARAMS(Args) Args
#  else
#   define PARAMS(Args) ()
#  endif
# endif

void mode_string PARAMS ((mode_t mode, char *str));

#ifdef __cplusplus // AEK
}
#endif

#endif
