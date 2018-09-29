#ifndef FILEMODE_H_

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
/*
vim:tabstop=2:shiftwidth=2:expandtab
*/
