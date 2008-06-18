/*   
 *   This is part of Remote System Call (RSC) Library.
 *
 *   aconv.c: Architecture conversion functions
 *   
 *   Copyright (C) 2007 Andrea Forni
 *   
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License, version 2, as
 *   published by the Free Software Foundation.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License along
 *   with this program; if not, write to the Free Software Foundation, Inc.,
 *   51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA.
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <strings.h>
#include <limits.h>
#include <arpa/inet.h>
#include <sys/utsname.h>
#include <sys/types.h>
#define __USE_LARGEFILE64
#include <dirent.h>
#include "aconv.h"
#include <time.h>
#include <sys/time.h>
#include <linux/utime.h>
#include <sys/utsname.h>
#include <sys/timex.h>
#include <sys/vfs.h>
#include <sys/stat.h>

#if 0
static void dump(void *p, int size, int bytenum) {
  int i;
  fprintf(stderr, "Mem %p[%d bytes]:", p, size);
  for(i = 0; i < size;  i++) {
    if(i % bytenum == 0)
      fprintf(stderr, "\n\t%p:\t", p+i);

    fprintf(stderr, "%.2X", 0xFF & *(char *)(p+i));
  }
  fprintf(stderr, "\n");
}
#endif

static char *arch2str[] = { "ARCH ERROR", "x86", "x86_64", "ppc", "ppc_64" };

char *aconv_arch2str(enum arch arch) {
  switch(arch) {
    case ACONV_X86:
      return arch2str[1];
      break;
    case ACONV_X86_64:
      return arch2str[2];
      break;
    case ACONV_PPC:
      return arch2str[3];
      break;
    case ACONV_PPC_64:
      return arch2str[4];
      break;
    default:
      return arch2str[0];
      break;
  }
}

static int get_host_endianess() {
  int i = 0x00000001;
  char *c = (char *)&i;
  if(*c == 0x01)
    return ACONV_LITTLEE;
  else
    return ACONV_BIGE;
}

enum arch aconv_get_host_arch() {
  int bitnum;
  if(sizeof(long) == 4)
    bitnum = ACONV_32BIT;
  else if(sizeof(long) == 8)
    bitnum = ACONV_64BIT;
  else 
    return ACONV_ARCH_ERROR;

  return bitnum | get_host_endianess();
}


#define pad(size, bitnum)      (((size) % ((bitnum)/8) == 0) ? 0 : (((((size) / ((bitnum)/8)) + 1) * ((bitnum)/8)) - (size)))
/* #define pad(size, bitnum)   ((size % 2 == 0) ? ((size) % ((bitnum) / 8)) : (((bitnum) / 8) - ((size) % ((bitnum) / 8)))) */

/* Swap bytes in 64 bit value */
#define bswap_64(x)\
  ((((x) & 0xff00000000000000) >> 56) | \
   (((x) & 0x00ff000000000000) >> 40) | \
   (((x) & 0x0000ff0000000000) >> 24) | \
   (((x) & 0x000000ff00000000) >>  8) | \
   (((x) & 0x00000000ff000000) <<  8) | \
   (((x) & 0x0000000000ff0000) << 24) | \
   (((x) & 0x000000000000ff00) << 40) | \
   (((x) & 0x00000000000000ff) << 56))
/* Swap bytes in 32 bit value */
#define bswap_32(x)\
  ((((x) & 0xff000000) >> 24) | (((x) & 0x00ff0000) >>  8) | \
   (((x) & 0x0000ff00) <<  8) | (((x) & 0x000000ff) << 24))
/* Swap bytes in 16 bit value.  */
#define bswap_16(x) \
       ((((x) & 0xff00) >> 8)  | (((x) & 0x00ff) << 8))
/* byte number conversion of 16/32/64 bit number, from endianess 'from'
 * to endianess 'to' */
#define bn_conv64(i, from, to) (((from) != (to)) ? (bswap_64((i))) : (i))
#define bn_conv32(i, from, to) (((from) != (to)) ? (bswap_32((i))) : (i))
#define bn_conv16(i, from, to) (((from) != (to)) ? (bswap_16((i))) : (i))

int aconv_char_size(from, to) { 
  return sizeof(char); 
}
int aconv_u_char_size(from, to) { 
  return sizeof(unsigned char); 
}
int aconv_short_size(from, to) { 
  return sizeof(short); 
}
int aconv_u_short_size(from, to) { 
  return sizeof(unsigned short); 
}
int aconv_int_size(from, to) { 
  return sizeof(int); 
}
int aconv_u_int_size(from, to) { 
  return sizeof(unsigned int); 
}
int aconv_u_long_size(from, to) { 
  return aconv_long_size(from, to); 
}
int aconv_longlong_size(from, to) { 
  return sizeof(long long); 
}
int aconv_u_longlong_size(from, to) { 
  return sizeof(unsigned long long); 
}


int aconv_char(char *c, enum arch from, enum arch to, void *p) {
  if(from == to)
    return ACONV_UNNEC;
  
  /* if the pointer isn't NULL I copy the value */
  if(p != NULL) {
    bzero(p, aconv_char_size(from, to));
    *((char *)p) = *c;
  }
  return ACONV_OK;
}

int aconv_u_char(unsigned char *c, enum arch from, enum arch to, void *p) {
  if(from == to)
    return ACONV_UNNEC;
  
  /* if the pointer isn't NULL I copy the value */
  if(p != NULL) {
    bzero(p, aconv_char_size(from, to));
    *((unsigned char *)p) = *c;
  }
  return ACONV_OK;
}

int aconv_short(short *i, enum arch from, enum arch to, void *p) {
  int from_e, to_e;
  short out;
  if(from == to)
    return ACONV_UNNEC;
  
  from_e  = from & ACONV_ENDIENESS_MASK;
  to_e    = to & ACONV_ENDIENESS_MASK;
  out = *i;
  /* Endieness: if it's different, I swap the byte  */
  if(from_e != to_e )
    out = bn_conv16(out, from_e, to_e);
  if(p != NULL) {
    *((short *)p) = out;
    return ACONV_OK;
  }
  *i = out;
  return ACONV_OK;
}

int aconv_u_short(unsigned short *i, enum arch from, enum arch to, void *p) {
  int from_e, to_e;
  unsigned short out;
  if(from == to)
    return ACONV_UNNEC;
  
  from_e  = from & ACONV_ENDIENESS_MASK;
  to_e    = to & ACONV_ENDIENESS_MASK;
  out = *i;
  /* Endieness: if it's different, I swap the byte  */
  if(from_e != to_e )
    out = bn_conv16(out, from_e, to_e);
  if(p != NULL) {
    *((unsigned short *)p) = out;
    return ACONV_OK;
  }
  *i = out;
  return ACONV_OK;
}

int aconv_int(int *i, enum arch from, enum arch to, void *p) {
  int from_e, to_e;
  int out;
  if(from == to)
    return ACONV_UNNEC;
  
  from_e  = from & ACONV_ENDIENESS_MASK;
  to_e    = to & ACONV_ENDIENESS_MASK;
  out = *i;
  /* Endieness */
  if(from_e != to_e )
    out = bn_conv32(out, from_e, to_e);
  
  if(p != NULL) {
    *((int*)p) = out;
    return ACONV_OK;
  }
  *i = out;
  return ACONV_OK;
}

int aconv_u_int(unsigned int *i, enum arch from, enum arch to, void *p) {
  int from_e, to_e;
  unsigned int out;
  if(from == to)
    return ACONV_UNNEC;
  
  from_e  = from & ACONV_ENDIENESS_MASK;
  to_e    = to & ACONV_ENDIENESS_MASK;
  out = *i;
  /* Endieness */
  if(from_e != to_e )
    out = bn_conv32(out, from_e, to_e);
  
  if(p != NULL) {
    *((unsigned int*)p) = out;
    return ACONV_OK;
  }
  *i = out;
  return ACONV_OK;
}

int aconv_long_size(enum arch from, enum arch to) {
  int from_bn, to_bn; /* bn = bitnumber */
  from_bn = from & ACONV_BITNUM_MASK;
  to_bn = to & ACONV_BITNUM_MASK;
  if(from_bn == to_bn)
    return sizeof(long);
  /* 32 => 64 */
  if(from_bn == ACONV_32BIT && to_bn == ACONV_64BIT)
    return 8;
  else
  /* 64 => 32 */
    return 4;
}

int aconv_long(long *l, enum arch from, enum arch to, void *p) {
  int from_bn, to_bn;
  int from_e, to_e;
  int ret;
  void *in, *out;
  if(from == to)
    return ACONV_UNNEC;

  from_bn = from & ACONV_BITNUM_MASK;
  to_bn = to & ACONV_BITNUM_MASK;
  from_e = from & ACONV_ENDIENESS_MASK;
  to_e = to & ACONV_ENDIENESS_MASK;
  ret = ACONV_OK;
  out = l;
  in = l;
  if(p != NULL)
    out = p;
  if(from_bn != to_bn) {
    if(p == NULL)
      return ACONV_ERROR;
    ret = ACONV_OK; 
    bzero(out, aconv_long_size(from, to));

	  /* 32 bit => 64 bit */
	  if(from_bn == ACONV_32BIT && to_bn == ACONV_64BIT) {
      /* The cast extend the sign of the number */
	    *((int64_t *)out) = (int64_t)(*l);
	  /* 64 bit => 32 bit */
	  } else {
	    /* int is always 32 bit */
	    if(*l > INT_MAX)
	      *((int32_t *)out) = INT_MAX;
      else if(*l < INT_MIN)
	      *((int32_t *)out) = INT_MIN;
	    else {
        /* If the from arch is big-endian I need to use
         * a bitmask to get the right data */
        /* big64 => {big32 | little32} */
        if(from_e == ACONV_BIGE) {
	        *((int32_t *)out) = (*l & 0x00000000ffffffff);
          /* little64 => big32 */
        } else  {
	        *((int32_t *)out) = *((int32_t *)l);
        }
      }
	  } 
    /* in this way the endianess code will use the content of 
     * 'out' insetead of the content of 'l' */
    in = out;
  }

  /* Here 'lp' points to 'p' is the bit number is different,
   * otherwise it points to 'l'.
   * Now I manage the endieness */
  if(from_e != to_e) {
    /* If the endianess is different, I swap the bit, i don't care
     * of the 'from' and 'to' endianess, I care only of the bit 
     * number */
    if(from_bn == to_bn) {
      if(from_bn == ACONV_32BIT)
        *((int32_t *)out) = bn_conv32(*((int32_t *)in), from_e, to_e);
      else {
/* In a32bit architecture 'in' (which is equal to the 32bit long 'l')
 * cannot be casted to int64 without a warning of the compiler */
# if __WORDSIZE == 64
        *((int64_t *)out) = bn_conv64(*((int64_t *)in), from_e, to_e);
# endif
      }
    } else {
      if(from_bn == ACONV_32BIT && to_bn == ACONV_64BIT)
        *((int64_t *)out) = bn_conv64(*((int64_t *)in), from_e, to_e);
      else
        *((int32_t *)out) = bn_conv32(*((int32_t *)in), from_e, to_e);
    }
  }

  return ret;
}


int aconv_u_long(unsigned long *l, enum arch from, enum arch to, void *p) {
  int from_bn, to_bn;
  int from_e, to_e;
  int ret;
  void *in, *out;
  if(from == to)
    return ACONV_UNNEC;

  from_bn = from & ACONV_BITNUM_MASK;
  to_bn = to & ACONV_BITNUM_MASK;
  from_e = from & ACONV_ENDIENESS_MASK;
  to_e = to & ACONV_ENDIENESS_MASK;
  ret = ACONV_OK;
  out = l;
  in = l;
  if(p != NULL)
    out = p;
  if(from_bn != to_bn) {
    if(p == NULL)
      return ACONV_ERROR;
    ret = ACONV_OK; 
    bzero(out, aconv_u_long_size(from, to));

	  /* 32 bit => 64 bit */
	  if(from_bn == ACONV_32BIT && to_bn == ACONV_64BIT) {
      /* The cast extend the sign of the number */
	    *((uint64_t *)out) = (uint64_t)(*l);
	  /* 64 bit => 32 bit */
	  } else {
	    /* int is always 32 bit */
	    if(*l > UINT_MAX)
	      *((uint32_t *)out) = UINT_MAX;
	    else {
        /* If the from arch is big-endian I need to use
         * a bitmask to get the right data */
        /* big64 => {big32 | little32} */
        if(from_e == ACONV_BIGE) {
	        *((uint32_t *)out) = (*l & 0x00000000ffffffff);
          /* little64 => big32 */
        } else  {
	        *((uint32_t *)out) = *((uint32_t *)l);
        }
      }
	  } 
    /* in this way the endianess code will use the content of 
     * 'out' insetead of the content of 'l' */
    in = out;
  }

  /* Here 'lp' points to 'p' is the bit number is different,
   * otherwise it points to 'l'.
   * Now I manage the endieness */
  if(from_e != to_e) {
    /* If the endianess is different, I swap the bit, i don't care
     * of the 'from' and 'to' endianess, I care only of the bit 
     * number */
    if(from_bn == to_bn) {
      if(from_bn == ACONV_32BIT)
        *((uint32_t *)out) = bn_conv32(*((uint32_t *)in), from_e, to_e);
      else {
/* In a 32bit architecture 'in' (which is equal to the 32bit long 'l')
 * cannot be casted to int64 without a warning of the compiler */
# if __WORDSIZE == 64
        *((uint64_t *)out) = bn_conv64(*((uint64_t *)in), from_e, to_e);
# endif
      }
    } else {
      if(from_bn == ACONV_32BIT && to_bn == ACONV_64BIT)
        *((uint64_t *)out) = bn_conv64(*((uint64_t *)in), from_e, to_e);
      else
        *((uint32_t *)out) = bn_conv32(*((uint32_t *)in), from_e, to_e);
    }
  }

  return ret;
}

int aconv_longlong(long long *l, enum arch from, enum arch to, void *p) {
  int from_e, to_e;
  long long out;
  if(from == to)
    return ACONV_UNNEC;
  
  from_e  = from & ACONV_ENDIENESS_MASK;
  to_e    = to & ACONV_ENDIENESS_MASK;
  out = *l;
  /* Endieness */
  if(from_e != to_e )
    out = bn_conv64(out, from_e, to_e);
  
  if(p != NULL) {
    *((long long *)p) = out;
    return ACONV_OK;
  }
  *l = out;
  return ACONV_OK;
}

int aconv_u_longlong(unsigned long long *l, enum arch from, enum arch to, void *p) {
  int from_e, to_e;
  unsigned long long out;
  if(from == to)
    return ACONV_UNNEC;
  
  from_e  = from & ACONV_ENDIENESS_MASK;
  to_e    = to & ACONV_ENDIENESS_MASK;
  out = *l;
  /* Endieness */
  if(from_e != to_e )
    out = bn_conv64(out, from_e, to_e);
  
  if(p != NULL) {
    *((unsigned long long *)p) = out;
    return ACONV_OK;
  }
  *l = out;
  return ACONV_OK;
}

int aconv_pointer_size(enum arch from, enum arch to) {
  int to_bn;
  to_bn = to & ACONV_BITNUM_MASK;
  if(to_bn == ACONV_64BIT)
    return 8;
  return 4;
}

int aconv_pointer(void *p, enum arch from, enum arch to, void *dest) {
  unsigned long l = (unsigned long)p;
  return aconv_u_long(&l, from, to, (void *)dest);
}
#if 0
int aconv_pointer(void *p, enum arch from, enum arch to, void **dest) {
  int from_bn, to_bn;
  int size = aconv_pointer_size(from, to);
  from_bn = from & ACONV_BITNUM_MASK;
  to_bn = to & ACONV_BITNUM_MASK;
  if(from == to || from_bn == to_bn)
    return ACONV_UNNEC;

  /* Convert a pointer between different architectures is meaningless, 
   * so the only thing I do is to return the pointer with the 
   * right bit number */
  if(dest != NULL) {
    bzero(dest, size);
    /* I need to control the value I put on 'dest' because if
     * *p = 0x0000000012345678 or *p = 0x1234567800000000 
     * I could copy the 0x00000000 part of the address into 
     * *dest, but *p isn't NULL */
    if(p != NULL && from_bn == ACONV_64BIT && to_bn == ACONV_32BIT) {
#if __WORDSIZE == 64
      if((0x00000000FFFFFFFF & (long)p) != NULL)
        *dest = (u_int32_t)(0x00000000FFFFFFFF & (long)p);
      else
        *dest = (u_int32_t)((0xFFFFFFFF00000000 & (long)p) >> 32);
#endif
    } else
      *dest = p;
  }

  return ACONV_OK;
}
#endif

int aconv_string_size(char *s, enum arch from, enum arch to) {
  return (strlen(s) + 1 ) * aconv_char_size(from, to);
}

int aconv_string(char *s, enum arch from, enum arch to, void *p) {
  if(from == to)
    return ACONV_UNNEC;
  
  if(p != NULL)
    strncpy(p, s, aconv_string_size(s, from, to));

  return ACONV_OK;
}

/**************************************************************************/
/* xxx_t type menagement                                                  */
/**************************************************************************/
int aconv_mode_t_size(from, to) {
	assert(sizeof(mode_t) == 4);
	return sizeof(mode_t);
}
int aconv_loff_t_size(from, to) {
	assert(sizeof(loff_t) == 8);
	return sizeof(loff_t);
}
int aconv_uid_t_size(from, to) {
	assert(sizeof(uid_t) == 4);
	return sizeof(uid_t);
}
int aconv_gid_t_size(from, to) {
	assert(sizeof(gid_t) == 4);
	return sizeof(gid_t);
}
int aconv_clockid_t_size(from, to) {
	assert(sizeof(clockid_t) == 4);
	return sizeof(clockid_t);
}
int aconv___off64_t_size(from, to) {
	assert(sizeof(__off64_t) == 8);
	return sizeof(__off64_t);
}
int aconv_socklen_t_size(from, to) {
	assert(sizeof(socklen_t) == 4);
	return sizeof(socklen_t);
}

int aconv_mode_t(mode_t *n, enum arch from, enum arch to, void *p) {
  assert(sizeof(mode_t) == 4);
  return aconv_u_int((unsigned int *)n, from, to, p);
}

int aconv_loff_t(loff_t *n, enum arch from, enum arch to, void *p) {
  assert(sizeof(loff_t) == 8);
  return aconv_longlong((long long *)n, from, to, p);
}

int aconv_uid_t(uid_t *n, enum arch from, enum arch to, void *p) {
  assert(sizeof(uid_t) == 4);
  return aconv_u_int((unsigned int *)n, from, to, p);
}

int aconv_gid_t(gid_t *n, enum arch from, enum arch to, void *p) {
  assert(sizeof(gid_t) == 4);
  return aconv_u_int((unsigned int *)n, from, to, p);
}
int aconv_clockid_t(clockid_t *n, enum arch from, enum arch to, void *p){
  assert(sizeof(clockid_t) == 4);
  return aconv_int((int *)n, from, to, p);
}
int aconv___off64_t(__off64_t *n, enum arch from, enum arch to, void *p) {
  assert(sizeof(__off64_t) == 8);
  return aconv_longlong((long long *)n, from, to, p);
}
int aconv_socklen_t(socklen_t *n, enum arch from, enum arch to, void *p) {
  assert(sizeof(socklen_t) == 4);
  return aconv_u_int((unsigned int *)n, from, to, p);
}

/* The type 'size_t' has different size that depends from
 * the architecture: it's a 'unsigned int' in ppc and x86, and
 * it's a 'unsigned long' in ppc64 and x86_64 */
int aconv_size_t_size(enum arch from, enum arch to) {
  if((to & ACONV_BITNUM_MASK) == ACONV_64BIT)
    return aconv_u_long_size(from, to);
  else 
    return aconv_u_int_size(from, to);
}

int aconv_size_t(size_t *n, enum arch from, enum arch to, void *p) {
  int from_bn, to_bn, ret;
  if(from == to)
    return ACONV_UNNEC;
  from_bn = from & ACONV_BITNUM_MASK;
  to_bn   = to   & ACONV_BITNUM_MASK;

  if(from_bn == ACONV_32BIT && to_bn == ACONV_32BIT) {
    ret = aconv_u_int((unsigned int *)n, from, to, p);
  } else {
    /* One or both architectures use 64bit. Here I use always the
     * aconv_u_long() function because if:
     * - both are 64bit: size_t is an 'unsigned long'
     * - from 32 to 64 : into 32bit arch 'int == long' so aconv_u_long() takes
     *                   care of the conversion
     * - from 64 to 32 : aconv_u_long() takes care of the conversion between 
     *                   64bit long and 32bit long, and seeing that 'int == long'
     *                   in the latter architecture, all works well.
     */
    ret = aconv_u_long((unsigned long *)n, from, to, p);
  }

  return ret;
}

int aconv_off_t_size(enum arch from, enum arch to) {
  if((to & ACONV_BITNUM_MASK) == ACONV_64BIT)
    return aconv_u_long_size(from, to);
  else 
    return aconv_u_int_size(from, to);
}

int aconv_off_t(off_t *n, enum arch from, enum arch to, void *p) {
  int from_bn, to_bn, ret;
  if(from == to)
    return ACONV_UNNEC;
  from_bn = from & ACONV_BITNUM_MASK;
  to_bn   = to   & ACONV_BITNUM_MASK;

  if(from_bn == ACONV_32BIT && to_bn == ACONV_32BIT) {
    ret = aconv_u_int((unsigned int *)n, from, to, p);
  } else {
    /* See the explanation into the aconv_size_t() function */
    ret = aconv_u_long((unsigned long *)n, from, to, p);
  }

  return ret;
}

int aconv___ino64_t_size(enum arch from, enum arch to) {
  return aconv_u_longlong_size(from, to);
}
int aconv___ino64_t(__ino64_t *n, enum arch from, enum arch to, void *p) {
  return aconv_u_longlong((unsigned long long *)n, from, to, p);
}

int aconv_sa_family_t_size(enum arch from, enum arch to) {
  return aconv_u_short_size(from, to);
}
int aconv_sa_family_t(sa_family_t *n, enum arch from, enum arch to, void *p) {
  return aconv_u_short((unsigned short *)n, from, to, p);
}

int aconv_time_t_size(enum arch from, enum arch to) {
  return aconv_long_size(from, to);
}
int aconv_time_t(time_t *n, enum arch from, enum arch to, void *p) {
  return aconv_long((long *)n, from, to, p);
}

int aconv_suseconds_t_size(enum arch from, enum arch to) {
  return aconv_long_size(from, to);
}
int aconv_suseconds_t(suseconds_t *n, enum arch from, enum arch to, void *p) {
  return aconv_long((long *)n, from, to, p);
}
/**************************************************************************/
/**************************************************************************/
/* Array and structs                                                      */
/**************************************************************************/
/* Returns the size of an fixed-length arrays of "elnum" homogeneous elements
 * The size of each element is returned by 'size_fun'.
 * NOTE: If the array is an array of pointers, the size of each element is
 * 4 bytes (for 32 bits architectures) or 8 bytes (for 64 bits architectures),
 * not the size of the pointed memory.
 * */
int aconv_array_size(enum arch from, enum arch to, int elnum, aconv_size_fun size_fun) {
  return (elnum * size_fun(from, to));
}

int aconv_array(void *a, enum arch from, enum arch to, int elnum, void *p,
    aconv_size_fun size_fun, aconv_fun aconv_fun) {
  int i, from_size, to_size;
  if(from == to)
    return ACONV_UNNEC;
  from_size = size_fun(to, from);
  to_size = size_fun(from, to);
  if(p != NULL) {
    for(i = 0; i < elnum; i++) {
      aconv_fun(a + (from_size * i), from, to, p + (to_size * i));
    }
  } else 
    for(i = 0; i < elnum; i++) 
      aconv_fun(a + (to_size * i), from, to, NULL);

  return ACONV_OK;
}



/*
 * TODO List:
 * - 'socklen_t'          done
 * - 'socklen_t *'        done
 * - 'struct dirent64 *'  done
 * - 'struct sockaddr *'  done
 * - 'struct stat64 *'
 * - 'struct statfs64 *'  done
 * - 'struct timespec *'  done
 * - 'struct timeval'     done
 * - 'struct timex *'     done
 * - 'struct timezone *'  done
 * - 'struct utimbuf *'   done
 * - 'struct utsname *'   done
 * - 'uid_t'              done
 * - 'void *'
*/
int aconv_struct_dirent64_size(enum arch from, enum arch to) {
  int s;
  int bitnum = to;
  s = aconv___ino64_t_size(from, to) +
      aconv___off64_t_size(from, to) +
      aconv_u_short_size(from, to) +
      aconv_u_char_size(from, to) +
      aconv_array_size(from, to, 256, aconv_char_size);
  /* On ppc32 the structure alignment is of 8 byte */
  if(to == ACONV_PPC)
    bitnum = ACONV_64BIT;
  s += pad(s, bitnum);
  return s;
}

int aconv_struct_dirent64(struct dirent64 *d, enum arch from, enum arch to, void *p) {
  int s1, s2, s3, s4;
  if(from == to)
    return ACONV_UNNEC;
  s1 = aconv___ino64_t_size(from, to);
  s2 = aconv___off64_t_size(from, to);
  s3 = aconv_u_short_size(from, to);
  s4 = aconv_u_char_size(from, to);
  if(aconv___ino64_t(&d->d_ino, from, to, p) == ACONV_ERROR)
    return ACONV_ERROR;
  if(aconv___off64_t(&d->d_off, from, to, p+s1) == ACONV_ERROR)
    return ACONV_ERROR;
  if(aconv_u_short(&d->d_reclen, from, to, p+s1+s2) == ACONV_ERROR)
    return ACONV_ERROR;
  if(aconv_u_char(&d->d_type, from, to, p+s1+s2+s3) == ACONV_ERROR)
    return ACONV_ERROR;
  if(aconv_array(d->d_name, from, to, 256, p+s1+s2+s3+s4, aconv_char_size, aconv_char) == ACONV_ERROR)
    return ACONV_ERROR;

  return ACONV_OK;
}
int aconv_struct_sockaddr_size(enum arch from, enum arch to) {
  return (
      aconv_sa_family_t_size(from, to) + 
      aconv_array_size(from, to, 14, aconv_char_size));
}

int aconv_struct_sockaddr(struct sockaddr *s, enum arch from, enum arch to, void *p) {
  int s1;
  if(from == to)
    return ACONV_UNNEC;
  
  s1 = aconv_sa_family_t_size(from, to);
  if(aconv_sa_family_t(&s->sa_family, from, to, p) == ACONV_ERROR)
    return ACONV_ERROR;
  if(aconv_array(s->sa_data, from, to, 14, p+s1, aconv_char_size, aconv_char) == ACONV_ERROR)
    return ACONV_ERROR;

  return ACONV_OK;
}

int aconv_struct_timespec_size(enum arch from, enum arch to) {
  return (
      aconv_time_t_size(from, to) + 
      aconv_long_size(from, to));
}

int aconv_struct_timespec(struct timespec *s, enum arch from, enum arch to, void *p) {
  int s1;
  if(from == to)
    return ACONV_UNNEC;
  s1 = aconv_time_t_size(from, to);
  if(aconv_time_t(&s->tv_sec, from, to, p) == ACONV_ERROR)
    return ACONV_ERROR;
  if(aconv_long(&s->tv_nsec, from, to, p + s1) == ACONV_ERROR)
    return ACONV_ERROR;

  return ACONV_OK;
}

int aconv_struct_timeval_size(enum arch from, enum arch to) {
  return (
      aconv_time_t_size(from, to) + 
      aconv_suseconds_t_size(from, to));
}

int aconv_struct_timeval(struct timeval *s, enum arch from, enum arch to, void *p) {
  int s1;
  if(from == to)
    return ACONV_UNNEC;

  s1 = aconv_time_t_size(from, to);
  if(aconv_time_t(&s->tv_sec, from, to, p) == ACONV_ERROR)
    return ACONV_ERROR;
  if(aconv_suseconds_t(&s->tv_usec, from, to, p+s1) == ACONV_ERROR)
    return ACONV_ERROR;

  return ACONV_OK;
}

int aconv_struct_timezone_size(enum arch from, enum arch to) {
  return (
      aconv_int_size(from, to) + 
      aconv_int_size(from, to));
}

int aconv_struct_timezone(struct timezone *s, enum arch from, enum arch to, void *p) {
  int s1;
  if(from == to)
    return ACONV_UNNEC;
  s1 = aconv_int_size(from, to);
  if(aconv_int(&s->tz_minuteswest, from, to, p) == ACONV_ERROR)
    return ACONV_ERROR;
  if(aconv_int(&s->tz_dsttime, from, to, p+s1) == ACONV_ERROR)
    return ACONV_ERROR;

  return ACONV_OK;
}

int aconv_struct_utimbuf_size(enum arch from, enum arch to) {
  return (
      aconv_time_t_size(from, to) + 
      aconv_time_t_size(from, to));
}

int aconv_struct_utimbuf(struct utimbuf *s, enum arch from, enum arch to, void *p) {
  int s1;
  if(from == to)
    return ACONV_UNNEC;

  s1 = aconv_time_t_size(from, to);
  if(aconv_time_t(&s->actime, from, to, p) == ACONV_ERROR)
    return ACONV_ERROR;
  if(aconv_time_t(&s->modtime, from, to, p+s1) == ACONV_ERROR)
    return ACONV_ERROR;

  return ACONV_OK;
}

int aconv_struct_utsname_size(enum arch from, enum arch to) {
  return (
      aconv_array_size(from, to, _UTSNAME_SYSNAME_LENGTH, aconv_char_size) +
      aconv_array_size(from, to, _UTSNAME_NODENAME_LENGTH, aconv_char_size) +
      aconv_array_size(from, to, _UTSNAME_RELEASE_LENGTH, aconv_char_size) +
      aconv_array_size(from, to, _UTSNAME_VERSION_LENGTH, aconv_char_size) +
      aconv_array_size(from, to, _UTSNAME_MACHINE_LENGTH, aconv_char_size) +
      aconv_array_size(from, to, _UTSNAME_DOMAIN_LENGTH, aconv_char_size));
}

int aconv_struct_utsname(struct utsname *s, enum arch from, enum arch to, void *p) {
  int s1, s2, s3, s4, s5;
  if(from == to)
    return ACONV_UNNEC;

  s1 = aconv_array_size(from, to, _UTSNAME_SYSNAME_LENGTH, aconv_char_size);
  s2 = aconv_array_size(from, to, _UTSNAME_NODENAME_LENGTH, aconv_char_size);
  s3 = aconv_array_size(from, to, _UTSNAME_RELEASE_LENGTH, aconv_char_size);
  s4 = aconv_array_size(from, to, _UTSNAME_VERSION_LENGTH, aconv_char_size);
  s5 = aconv_array_size(from, to, _UTSNAME_MACHINE_LENGTH, aconv_char_size);
  if(aconv_array(s->sysname, from, to, _UTSNAME_SYSNAME_LENGTH, p, aconv_char_size, aconv_char) == ACONV_ERROR)
    return ACONV_ERROR;
  if(aconv_array(s->nodename, from, to, _UTSNAME_NODENAME_LENGTH, p+s1, aconv_char_size, aconv_char) == ACONV_ERROR)
    return ACONV_ERROR;
  if(aconv_array(s->release, from, to, _UTSNAME_RELEASE_LENGTH, p+s1+s2, aconv_char_size, aconv_char) == ACONV_ERROR)
    return ACONV_ERROR;
  if(aconv_array(s->version, from, to, _UTSNAME_VERSION_LENGTH, p+s1+s2+s3, aconv_char_size, aconv_char) == ACONV_ERROR)
    return ACONV_ERROR;
  if(aconv_array(s->machine, from, to, _UTSNAME_MACHINE_LENGTH, p+s1+s2+s3+s4, aconv_char_size, aconv_char) == ACONV_ERROR)
    return ACONV_ERROR;
#if _UTSNAME_DOMAIN_LENGTH - 0
    /* Name of the domain of this node on the network.  */
# ifdef __USE_GNU
  if(aconv_array(s->domainname, from, to, _UTSNAME_DOMAIN_LENGTH, p+s1+s2+s3+s4+s5, aconv_char_size, aconv_char) == ACONV_ERROR)
# else
  if(aconv_array(s->__domainname, from, to, _UTSNAME_DOMAIN_LENGTH, p+s1+s2+s3+s4+s5, aconv_char_size, aconv_char) == ACONV_ERROR)
# endif
#endif
    return ACONV_ERROR;

  return ACONV_OK;
}

int aconv_struct_timex_size(enum arch from, enum arch to) {
  int s_u_int, s_long, s_int;
  s_u_int = aconv_u_int_size(from, to);
  s_int = aconv_int_size(from, to);
  s_long = aconv_long_size(from, to);
  return (s_u_int + pad(s_u_int, to) +
          s_long + s_long  + s_long + s_long + 
          s_int  + pad(s_int, to) +
          s_long  + s_long + s_long + 
          aconv_struct_timeval_size(from, to) + 
          s_long  + s_long + s_long  + 
          s_int + pad(s_int, to) +
          s_long  + s_long + s_long  + s_long + s_long + 
          12 * s_int);
}

int aconv_struct_timex(struct timex *t, enum arch from, enum arch to, void *p) {
  int s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12, s13, s14, s15, s16, s17, s18;

  if(from == to)
    return ACONV_UNNEC;
  s1 = aconv_u_int_size(from, to);
  s1 += pad(s1, to);
  s2 = aconv_long_size(from, to);
  s3 = s4 = s5 = s2;
  s6 = aconv_int_size(from, to);
  s6 += pad(s6, to);
  s7 = s8 = s9 = s2;
  s10 = aconv_struct_timeval_size(from, to);
  s11 = s12 = s13 = s2;
  s14 = s6;
  s15 = s16 = s17 = s18 = s2;

  if(aconv_u_int(&t->modes ,from, to, p) == ACONV_ERROR)
    return ACONV_ERROR;
  if(aconv_long(&t->offset ,from, to, p+s1) == ACONV_ERROR)
    return ACONV_ERROR;
  if(aconv_long(&t->freq ,from, to, p+s1+s2) == ACONV_ERROR)
    return ACONV_ERROR;
  if(aconv_long(&t->maxerror ,from, to, p+s1+s2+s3) == ACONV_ERROR)
    return ACONV_ERROR;
  if(aconv_long(&t->esterror ,from, to, p+s1+s2+s3+s4) == ACONV_ERROR)
    return ACONV_ERROR;
  if(aconv_int(&t->status ,from, to, p+s1+s2+s3+s4+s5) == ACONV_ERROR)
    return ACONV_ERROR;
  if(aconv_long(&t->constant ,from, to, p+s1+s2+s3+s4+s5+s6) == ACONV_ERROR)
    return ACONV_ERROR;
  if(aconv_long(&t->precision ,from, to, p+s1+s2+s3+s4+s5+s6+s7) == ACONV_ERROR)
    return ACONV_ERROR;
  if(aconv_long(&t->tolerance ,from, to, p+s1+s2+s3+s4+s5+s6+s7+s8) == ACONV_ERROR)
    return ACONV_ERROR;
  if(aconv_struct_timeval(&t->time ,from, to, p+s1+s2+s3+s4+s5+s6+s7+s8+s9) == ACONV_ERROR)
    return ACONV_ERROR;
  if(aconv_long(&t->tick ,from, to, p+s1+s2+s3+s4+s5+s6+s7+s8+s9+s10) == ACONV_ERROR)
    return ACONV_ERROR;
  if(aconv_long(&t->ppsfreq ,from, to, p+s1+s2+s3+s4+s5+s6+s7+s8+s9+s10+s11) == ACONV_ERROR)
    return ACONV_ERROR;
  if(aconv_long(&t->jitter ,from, to, p+s1+s2+s3+s4+s5+s6+s7+s8+s9+s10+s11+s12) == ACONV_ERROR)
    return ACONV_ERROR;
  if(aconv_int(&t->shift ,from, to, p+s1+s2+s3+s4+s5+s6+s7+s8+s9+s10+s11+s12+s13) == ACONV_ERROR)
    return ACONV_ERROR;
  if(aconv_long(&t->stabil ,from, to, p+s1+s2+s3+s4+s5+s6+s7+s8+s9+s10+s11+s12+s13+s14) == ACONV_ERROR)
    return ACONV_ERROR;
  if(aconv_long(&t->jitcnt ,from, to, p+s1+s2+s3+s4+s5+s6+s7+s8+s9+s10+s11+s12+s13+s14+s15) == ACONV_ERROR)
    return ACONV_ERROR;
  if(aconv_long(&t->calcnt ,from, to, p+s1+s2+s3+s4+s5+s6+s7+s8+s9+s10+s11+s12+s13+s14+s15+s16) == ACONV_ERROR)
    return ACONV_ERROR;
  if(aconv_long(&t->errcnt ,from, to, p+s1+s2+s3+s4+s5+s6+s7+s8+s9+s10+s11+s12+s13+s14+s15+s16+s17) == ACONV_ERROR)
    return ACONV_ERROR;
  if(aconv_long(&t->stbcnt ,from, to, p+s1+s2+s3+s4+s5+s6+s7+s8+s9+s10+s11+s12+s13+s14+s15+s16+s17+s18) == ACONV_ERROR)
    return ACONV_ERROR;

  return ACONV_OK;
}

int aconv_struct_statfs64_size(enum arch from, enum arch to) {
  int s;
  int bitnum = to;
  s = aconv_long_size(from, to) * 4 +
      aconv_longlong_size(from, to) * 5 + 
      aconv_array_size(from, to, 2, aconv_int_size) +
      aconv_array_size(from, to, 5, aconv_long_size);
  /* On ppc32 the structure alignment is of 8 byte */
  if(to == ACONV_PPC)
    bitnum = ACONV_64BIT;
  s += pad(s, bitnum);
  return s;
}

int aconv_struct_statfs64(struct statfs64 *s, enum arch from, enum arch to, void *p) {
  int sl, sll, sa1;
  if(from == to)
    return ACONV_UNNEC;
  sl = aconv_long_size(from, to);
  sll = aconv_longlong_size(from, to);
  sa1 = aconv_array_size(from, to, 2, aconv_int_size);
  if(aconv_long(&s->f_type,     from, to,     p) == ACONV_ERROR)
    return ACONV_ERROR;
  if(aconv_long(&s->f_bsize,    from, to,     p+sl) == ACONV_ERROR)
    return ACONV_ERROR;
  if(aconv_longlong(&s->f_blocks,   from, to, p+sl+sl) == ACONV_ERROR)
    return ACONV_ERROR;
  if(aconv_longlong(&s->f_bfree,    from, to, p+sl+sl+sll) == ACONV_ERROR)
    return ACONV_ERROR;
  if(aconv_longlong(&s->f_bavail,   from, to, p+sl+sl+sll+sll) == ACONV_ERROR)
    return ACONV_ERROR;
  if(aconv_longlong(&s->f_files,    from, to, p+sl+sl+sll+sll+sll) == ACONV_ERROR)
    return ACONV_ERROR;
  if(aconv_longlong(&s->f_ffree,    from, to, p+sl+sl+sll+sll+sll+sll) == ACONV_ERROR)
    return ACONV_ERROR;
  if(aconv_array(&s->f_fsid,    from, to, 2,  p+sl+sl+sll+sll+sll+sll+sll, aconv_int_size, aconv_int) == ACONV_ERROR)
    return ACONV_ERROR;
  if(aconv_long(&s->f_namelen,  from, to,     p+sl+sl+sll+sll+sll+sll+sll+sa1) == ACONV_ERROR)
    return ACONV_ERROR;
  if(aconv_long(&s->f_frsize,   from, to,     p+sl+sl+sll+sll+sll+sll+sll+sa1+sl) == ACONV_ERROR)
    return ACONV_ERROR;
  if(aconv_array(&s->f_spare,   from, to, 5,  p+sl+sl+sll+sll+sll+sll+sll+sa1+sl+sl, aconv_long_size, aconv_long) == ACONV_ERROR)
    return ACONV_ERROR;

  return ACONV_OK;
}

int aconv_struct_stat64_size(enum arch from, enum arch to) {
  int s;
  s = aconv___dev_t_size(from, to);
  if(to == ACONV_X86) {
    s += aconv_u_int_size(from, to) +  /* pad1 */
         aconv___ino_t_size(from, to);
  } else {
    s += aconv___ino64_t_size(from, to);
  }
  s += aconv___nlink_t_size(from, to) + 
       aconv___mode_t_size(from, to) +
       aconv___uid_t_size(from, to) +
       aconv___gid_t_size(from, to);
  if(to == ACONV_X86_64) {
    s += aconv_u_int_size(from, to) +  /* pad0 */
      aconv___dev_t_size(from, to) +
      aconv___off_t_size(from, to);
  } else if(to == ACONV_PPC_64) {
    s += aconv_u_int_size(from, to) +  /* pad0 */
      aconv___dev_t_size(from, to) +
      aconv___off64_t_size(from, to);
  } else if(to == ACONV_PPC) {
    s += aconv___dev_t_size(from, to) +
      aconv_u_short_size(from, to) + pad(aconv_u_short_size(from, to), ACONV_64BIT) + /* __pad2 */
      aconv___off64_t_size(from, to);
  } else {
    s += aconv___dev_t_size(from, to) +
      aconv_u_int_size(from, to) +  /* pad2 */
      aconv___off64_t_size(from, to);
  }
  s += aconv___blksize_t_size(from, to) +
      aconv___blkcnt64_t_size(from, to) +
#ifdef __USE_MISC
      aconv_struct_timespec_size(from, to) * 3;
#else
      aconv___time_t_size(from, to) * 3 +
      aconv_u_long_size(from, to) * 3;
#endif
  if(to == ACONV_X86) 
    s += aconv___ino64_t_size(from, to);
  else if(to == ACONV_PPC)
    s += aconv_u_long_size(from, to) * 2;
  else
    s += aconv_u_long_size(from, to) * 3;
  
  if(to == ACONV_PPC)  
    s += pad(s, ACONV_64BIT);
  else
    s += pad(s, to);

  return s;
}
int aconv_struct_stat64(struct stat64 *s, enum arch from, enum arch to, void *p) {
  int ret;
  void *mem = p;

  if(from == to)
    return ACONV_UNNEC;

	ret  = aconv___dev_t(&s->st_dev, from, to, mem); mem += aconv___dev_t_size(from, to);
  /* In x86 arch there is a __st_ino filed that is the 32 bit serial number, the other architectures
   * have only st_ino that is a 64 bit field, so I have to convert the 64bit filed to 32bit one
   * and if st_ino is too large I save into __st_ino the maximum value savable. */
  if(to == ACONV_X86) {
    /* There is a 'unsigned int' pad field after st_dev */
    mem += aconv_u_int_size(from, to);
    __ino_t ino;
    if(s->st_ino > UINT_MAX)
      ino = UINT_MAX;
    else
      ino = (__off_t)s->st_ino;
    ret = aconv___ino_t(&ino, from, to, mem); mem += aconv___ino_t_size(from, to); 
  } else {
	  ret = aconv___ino64_t(&s->st_ino, from, to, mem); mem += aconv___ino64_t_size(from, to);
  }
  /* Into ppc and x86 architectures st_mode and st_nlink fields are inverted */
  if(to == ACONV_PPC || to == ACONV_X86) {
	  ret = aconv___mode_t(&s->st_mode, from, to, mem); mem += aconv___mode_t_size(from, to);
	  ret = aconv___nlink_t(&s->st_nlink, from, to, mem); mem += aconv___nlink_t_size(from, to);
  } else {
	  ret = aconv___nlink_t(&s->st_nlink, from, to, mem); mem += aconv___nlink_t_size(from, to);
	  ret = aconv___mode_t(&s->st_mode, from, to, mem); mem += aconv___mode_t_size(from, to);
  }
	ret = aconv___uid_t(&s->st_uid, from, to, mem); mem += aconv___uid_t_size(from, to);
	ret = aconv___gid_t(&s->st_gid, from, to, mem);

  mem += aconv___gid_t_size(from, to);
  /* In ppc64 arch. there is a integer pad after st_gid field, instead in x86_64 there isn't
   * a pad field, but st_gid is 8byte aligned a*/
  if(to == ACONV_PPC_64)
     mem += aconv_int_size(from, to);
  else if(to == ACONV_X86_64)
    mem += pad(aconv___gid_t_size(from, to), to);
	ret = aconv___dev_t(&s->st_rdev, from, to, mem);

  mem += aconv___dev_t_size(from, to);
  /* In ppc arch. there is an 'unsigned short' pad after st_rdev, aligned to an 8 byte address.
   * In x86 arch. there is a 'unsigned int' pad field.  */
  if(to == ACONV_PPC)
     mem += aconv_u_short_size(from, to) + pad(aconv_u_short_size(from, to), ACONV_64BIT);
  else if(to == ACONV_X86)
    mem += aconv_u_int_size(from, to);


	ret = aconv___off64_t(&s->st_size, from, to, mem); 
  /* In x86_64 arch. st_size is of type __off_t and not __off64_t */
  if(to == ACONV_X86_64)
    mem += aconv___off_t_size(from, to);
  else
    mem += aconv___off64_t_size(from, to);
	ret = aconv___blksize_t(&s->st_blksize, from, to, mem); 
  mem += aconv___blksize_t_size(from, to);
  /* In ppc and 64bit architecture, the st_blksize filed is 8byte aligned */
  if(to != ACONV_X86)
    mem += pad(aconv___blksize_t_size(from, to), ACONV_64BIT);
	ret = aconv___blkcnt64_t(&s->st_blocks, from, to, mem); mem += aconv___blkcnt64_t_size(from, to);
#ifdef __USE_MISC
	ret = aconv_struct_timespec(&s->st_atim, from, to, mem); mem += aconv_struct_timespec_size(from, to);
	ret = aconv_struct_timespec(&s->st_mtim, from, to, mem); mem += aconv_struct_timespec_size(from, to);
	ret = aconv_struct_timespec(&s->st_ctim, from, to, mem); mem += aconv_struct_timespec_size(from, to);
#else
	ret = aconv___time_t(&s->st_atime, from, to, mem); mem += aconv___time_t_size(from, to);
	ret = aconv_u_long(&s->st_atimensec, from, to, mem); mem += aconv_u_long_size(from, to);
	ret = aconv___time_t(&s->st_mtime, from, to, mem); mem += aconv___time_t_size(from, to);
	ret = aconv_u_long(&s->st_mtimensec, from, to, mem); mem += aconv_u_long_size(from, to);
	ret = aconv___time_t(&s->st_ctime, from, to, mem); mem += aconv___time_t_size(from, to);
	ret = aconv_u_long(&s->st_ctimensec, from, to, mem); mem += aconv_u_long_size(from, to);
#endif
  /* In x86 arch. there is a st_ino filed at hte end of the structure */
  if(to == ACONV_X86)
	  ret = aconv___ino64_t(&s->st_ino, from, to, mem);


  return ACONV_OK;
}
int aconv_bytes_size(int bytenum, enum arch from, enum arch to) {
  return bytenum;
}
int aconv_bytes(void *b, enum arch from, enum arch to, void *p, int bytenum) {
  return aconv_array(b, from, to, bytenum, p, aconv_char_size, aconv_char);
}
