/****************************************************************************
 * libs/libc/string/lib_memrchr.c
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.  The
 * ASF licenses this file to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance with the
 * License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
 * License for the specific language governing permissions and limitations
 * under the License.
 *
 ****************************************************************************/

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <nuttx/config.h>

#include <string.h>

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

/* Nonzero if x is not aligned on a "long" boundary. */

#define UNALIGNED(x) ((long)((x) + 1) & (sizeof(long) - 1))

/* How many bytes are loaded each iteration of the word copy loop. */

#define LBLOCKSIZE (sizeof(long))

/* Threshhold for punting to the bytewise iterator. */

#define TOO_SMALL(len) ((len) < LBLOCKSIZE)

/* Macros for detecting endchar */

#if LONG_MAX == 2147483647
#  define DETECTNULL(x) (((x) - 0x01010101) & ~(x) & 0x80808080)
#elif LONG_MAX == 9223372036854775807
/* Nonzero if x (a long int) contains a NULL byte. */

#  define DETECTNULL(x) (((x) - 0x0101010101010101) & ~(x) & 0x8080808080808080)
#endif

#define DETECTCHAR(x, mask) (DETECTNULL((x) ^ (mask)))

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/****************************************************************************
 * Name: memrchr
 *
 * Description:
 *   The memrchr() function locates the last occurrence of 'c' (converted to
 *   an unsigned char) in the initial 'n' bytes (each interpreted as
 *   unsigned char) of the object pointed to by s.
 *
 * Returned Value:
 *   The memrchr() function returns a pointer to the located byte, or a null
 *   pointer if the byte does not occur in the object.
 *
 ****************************************************************************/

#undef memrchr /* See mm/README.txt */
FAR void *memrchr(FAR const void *s, int c, size_t n)
{
  FAR const unsigned char *src0 =
            (FAR const unsigned char *)s + n - 1;
  FAR unsigned long *asrc;
  unsigned char d = c;
  unsigned long mask;
  unsigned int i;

  while (UNALIGNED(src0))
    {
      if (!n--)
        {
          return NULL;
        }

      if (*src0 == d)
        {
          return (FAR void *)src0;
        }

      src0--;
    }

  if (!TOO_SMALL(n))
    {
      /* If we get this far, we know that n is large and src0 is
       * word-aligned.
       * The fast code reads the source one word at a time and only
       * performs the bytewise search on word-sized segments if they
       * contain the search character, which is detected by XORing
       * the word-sized segment with a word-sized block of the search
       * character and then detecting for the presence of NUL in the
       * result.
       */

      asrc = (FAR unsigned long *)(src0 - LBLOCKSIZE + 1);
      mask = d << 8 | d;
      mask = mask << 16 | mask;
      for (i = 32; i < LBLOCKSIZE * 8; i <<= 1)
        {
          mask = (mask << i) | mask;
        }

      while (n >= LBLOCKSIZE)
        {
          if (DETECTCHAR(*asrc, mask))
            {
              break;
            }

          n -= LBLOCKSIZE;
          asrc--;
        }

      /* If there are fewer than LBLOCKSIZE characters left,
       * then we resort to the bytewise loop.
       */

      src0 = (FAR unsigned char *)asrc + LBLOCKSIZE - 1;
    }

  while (n--)
    {
      if (*src0 == d)
        {
          return (FAR void *)src0;
        }

      src0--;
    }

  return NULL;
}
