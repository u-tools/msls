/* path-concat.c -- concatenate two arbitrary pathnames
   Copyright (C) 1996, 1997, 1998, 1999, 2000, 2001 Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.  */

/* Written by Jim Meyering.  */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#ifndef HAVE_MEMPCPY
# define mempcpy(D, S, N) ((void *) ((char *) memcpy (D, S, N) + (N)))
#endif

#include <stdio.h>

#if HAVE_STRING_H
# if !STDC_HEADERS && HAVE_MEMORY_H
#  include <memory.h>
# endif
# include <string.h>
#else
# if HAVE_STRINGS_H
#  include <strings.h>
# endif
#endif
#if HAVE_STDLIB_H
# include <stdlib.h>
#endif
#if HAVE_UNISTD_H
# include <unistd.h>
#endif

#ifndef HAVE_DECL_MALLOC
"this configure-time declaration test was not run"
#endif
#if !HAVE_DECL_MALLOC
char *malloc ();
#endif

#ifndef strdup
//char *strdup (); // AEK - decl is wrong on WIN32
#endif

#ifndef DIRECTORY_SEPARATOR
# define DIRECTORY_SEPARATOR '/'
#endif

#ifndef FILESYSTEM_PREFIX_LEN
# define FILESYSTEM_PREFIX_LEN(Filename) 0
#endif

#ifndef ISSLASH
# define ISSLASH(C) ((C) == DIRECTORY_SEPARATOR)
#endif

#include "xalloc.h"
#include "path-concat.h"

/* Concatenate two pathname components, DIR and BASE, in
   newly-allocated storage and return the result.  Return 0 if out of
   memory.  Add a slash between DIR and BASE in the result if neither
   would contribute one.  If each would contribute at least one, elide
   one from the end of DIR.  Otherwise, simply concatenate DIR and
   BASE.  In any case, if BASE_IN_RESULT is non-NULL, set
   *BASE_IN_RESULT to point to the copy of BASE in the returned
   concatenation.

   DIR may be NULL, BASE must not be.

   Return NULL if memory is exhausted.  */

#pragma warning(disable: 4018) // ok for signed/unsigned mismatch
#pragma warning(disable: 4715) // ok for not all paths to return a value

char *
path_concat (const char *dir, const char *base, char **base_in_result)
{
  char *p;
  char *p_concat;
  size_t base_len;
  size_t dir_len;

  if (!dir)
    {
      p_concat = strdup (base);
      if (base_in_result)
        *base_in_result = p_concat;
      return p_concat;
    }

  /* DIR is not empty. */
  base_len = strlen (base);
  dir_len = strlen (dir);

  p_concat = malloc (dir_len + base_len + 2);
  if (!p_concat)
    return 0;

  p = mempcpy (p_concat, dir, dir_len);

  //if (dir_len > FILESYSTEM_PREFIX_LEN (dir)) // BUG: This is wrong! - AEK
  if ((int)dir_len != FILESYSTEM_PREFIX_LEN(dir)) // fixed - AEK
    {
      if (ISSLASH (*(p - 1)) && ISSLASH (*base))
	--p;
      else if (!ISSLASH (*(p - 1)) && !ISSLASH (*base))
	*p++ = DIRECTORY_SEPARATOR;
    }

  if (base_in_result)
    *base_in_result = p;

  memcpy (p, base, base_len + 1);

  return p_concat;
}

/* Same, but die when memory is exhausted. */

char *
xpath_concat (const char *dir, const char *base, char **base_in_result)
{
  char *res = path_concat (dir, base, base_in_result);
  if (res)
    return res;
  xalloc_die ();
}
/*
vim:tabstop=8:shiftwidth=2:noexpandtab
*/
