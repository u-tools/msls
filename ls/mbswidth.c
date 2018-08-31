/* Determine the number of screen columns needed for a string.
   Copyright (C) 2000 Free Software Foundation, Inc.

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

/* Written by Bruno Haible <haible@clisp.cons.org>.  */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

/* Get MB_LEN_MAX.  */
#if HAVE_LIMITS_H
# include <limits.h>
#endif

/* Get MB_CUR_MAX.  */
#if HAVE_STDLIB_H
# include <stdlib.h>
#endif

#if HAVE_STRING_H
# include <string.h>
#endif

/* Get isprint().  */
#include <ctype.h>

/* Get mbstate_t, mbrtowc(), mbsinit(), wcwidth().  */
#if HAVE_WCHAR_H
# include <wchar.h>
#endif

/* Get iswprint().  */
#if HAVE_WCTYPE_H
# include <wctype.h>
#endif
#if !defined iswprint && !HAVE_ISWPRINT
# define iswprint(wc) 1
#endif

#ifndef HAVE_DECL_WCWIDTH
"this configure-time declaration test was not run"
#endif
#if !HAVE_DECL_WCWIDTH
int wcwidth ();
#endif

#ifndef wcwidth
# if !HAVE_WCWIDTH
/* wcwidth doesn't exist, so assume all printable characters have
   width 1.  */
#  define wcwidth(wc) ((wc) == 0 ? 0 : iswprint (wc) ? 1 : -1)
# endif
#endif

/* Get ISPRINT.  */
#if defined (STDC_HEADERS) || (!defined (isascii) && !defined (HAVE_ISASCII))
# define IN_CTYPE_DOMAIN(c) 1
#else
# define IN_CTYPE_DOMAIN(c) isascii(c)
#endif
/* Undefine to protect against the definition in wctype.h of solaris2.6.   */
#undef ISPRINT
#define ISPRINT(c) (IN_CTYPE_DOMAIN (c) && isprint (c))

#include "mbswidth.h"

#include "xmbrtowc.h" // AEK

/* Returns the number of columns needed to represent the multibyte
   character string pointed to by STRING.  If a non-printable character
   occurs, -1 is returned, unless MBSW_ACCEPT_UNPRINTABLE is specified.
   With flags = 0, this is the multibyte analogon of the wcswidth function.  */
int
mbswidth (const char *string, int flags)
{
  return mbsnwidth (string, strlen (string), flags);
}

/* Returns the number of columns needed to represent the multibyte
   character string pointed to by STRING of length NBYTES.  If a
   non-printable character occurs, -1 is returned, unless
   MBSW_ACCEPT_UNPRINTABLE is specified.  */
int
mbsnwidth (const char *string, size_t nbytes, int flags)
{
  const char *p = string;
  const char *plimit = p + nbytes;
  int width;

  width = 0;
#if HAVE_MBRTOWC && (MB_LEN_MAX > 1)
  if (MB_CUR_MAX > 1)
    {
      while (p < plimit)
	switch (*p)
	  {
	    case ' ': case '!': case '"': case '#': case '%':
	    case '&': case '\'': case '(': case ')': case '*':
	    case '+': case ',': case '-': case '.': case '/':
	    case '0': case '1': case '2': case '3': case '4':
	    case '5': case '6': case '7': case '8': case '9':
	    case ':': case ';': case '<': case '=': case '>':
	    case '?':
	    case 'A': case 'B': case 'C': case 'D': case 'E':
	    case 'F': case 'G': case 'H': case 'I': case 'J':
	    case 'K': case 'L': case 'M': case 'N': case 'O':
	    case 'P': case 'Q': case 'R': case 'S': case 'T':
	    case 'U': case 'V': case 'W': case 'X': case 'Y':
	    case 'Z':
	    case '[': case '\\': case ']': case '^': case '_':
	    case 'a': case 'b': case 'c': case 'd': case 'e':
	    case 'f': case 'g': case 'h': case 'i': case 'j':
	    case 'k': case 'l': case 'm': case 'n': case 'o':
	    case 'p': case 'q': case 'r': case 's': case 't':
	    case 'u': case 'v': case 'w': case 'x': case 'y':
	    case 'z': case '{': case '|': case '}': case '~':
	      /* These characters are printable ASCII characters.  */
	      p++;
	      width++;
	      break;
	    default:
	      /* If we have a multibyte sequence, scan it up to its end.  */
	      {
		mbstate_t mbstate;
		memset (&mbstate, 0, sizeof mbstate);
		do
		  {
		    wchar_t wc;
		    size_t bytes;
		    int w;

		    bytes = mbrtowc (&wc, p, plimit - p, &mbstate);

		    if (bytes == (size_t) -1)
		      /* An invalid multibyte sequence was encountered.  */
		      {
			if (flags & MBSW_ACCEPT_INVALID)
			  {
			    p++;
			    width++;
			    break;
			  }
			else
			  return -1;
		      }

		    if (bytes == (size_t) -2)
		      /* An incomplete multibyte character at the end.  */
		      {
			if (flags & MBSW_ACCEPT_INVALID)
			  {
			    p = plimit;
			    width++;
			    break;
			  }
			else
			  return -1;
		      }

		    if (bytes == 0)
		      /* A null wide character was encountered.  */
		      bytes = 1;

		    w = wcwidth (wc);
		    if (w >= 0)
		      /* A printable multibyte character.  */
		      width += w;
		    else
		      /* An unprintable multibyte character.  */
		      if (flags & MBSW_ACCEPT_UNPRINTABLE)
			width += 1;
		      else
			return -1;

		    p += bytes;
		  }
		while (! mbsinit (&mbstate));
	      }
	      break;
	  }
      return width;
    }
#endif

  while (p < plimit)
    {
      unsigned char c = (unsigned char) *p++;

      if ((flags & MBSW_ACCEPT_UNPRINTABLE) || ISPRINT (c))
	width++;
      else
	return -1;
    }
  return width;
}
