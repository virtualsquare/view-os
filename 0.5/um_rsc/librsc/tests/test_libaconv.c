/*   
 *   This is part of Remote System Call (RSC) Library.
 *
 *   test_libaconv.c: Architecture Conversion tests
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
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <limits.h>
#include "aconv.h"
#include <sys/types.h>
#define __USE_LARGEFILE64
#include <dirent.h>
#include <sys/utsname.h>
#include <sys/timex.h>
#include <sys/vfs.h>
#include <sys/stat.h>



/*******************************************************************/
/* Test size functions                                             */
/*******************************************************************/

static void test_size_fun(enum arch from, enum arch to) {
  assert(aconv_long_size(from, to) == sizeof(long));
  assert(aconv_u_long_size(from, to) == sizeof(unsigned long));
  
  assert(aconv___uid_t_size(from, to) == sizeof(__uid_t));
  assert(aconv___gid_t_size(from, to) == sizeof(__gid_t));
  assert(aconv___time_t_size(from, to) == sizeof(__time_t));
  assert(aconv___dev_t_size(from, to) == sizeof(__dev_t));
  assert(aconv___ino_t_size(from, to) == sizeof(__ino_t));
  assert(aconv___mode_t_size(from, to) == sizeof(__mode_t));
  assert(aconv___nlink_t_size(from, to) == sizeof(__nlink_t));
  assert(aconv___blksize_t_size(from, to) == sizeof(__blksize_t));
  assert(aconv___blkcnt64_t_size(from, to) == sizeof(__blkcnt64_t));
  
  assert(aconv___off_t_size(from, to) == sizeof(__off_t));
}

/*******************************************************************/
/* Test conversion functions                                       */
/*******************************************************************/
static void test_char_w(int fd, enum arch from, enum arch to) {
  char c[] = {0xF1, 0x02};
  int csize = sizeof(c) / sizeof(char);
  char *out;
  int ret, i;
  int size = aconv_char_size(from, to);
  assert(size == 1);
  for(i = 0; i < csize; i++) {
	  assert((out = malloc(size)) != NULL);
	  ret = aconv_char(&c[i], from, to, out);
	  if(from == to) {
	    assert(ret == ACONV_UNNEC);
      memcpy(out, &c[i], size);
    } else
	    assert(ret == ACONV_OK);
	  assert(write(fd, out, size) == size);
	  free(out);
	  
	  ret = aconv_char(&c[i], from, to, NULL);
	  if(from == to)
	    assert(ret == ACONV_UNNEC);
	  else
	    assert(ret == ACONV_OK);
	  assert(write(fd, &c[i], size) == size);
  }
}

static void test_char_r(int fd, enum arch from, enum arch to) {
  int i, size = sizeof(char);
  char *in;
  char c[] = {0xF1, 0x02};
  int csize = sizeof(c) / sizeof(char);
  assert(size == 1);
  for(i = 0; i < csize; i++) {
    assert((in = malloc(size)) != NULL);
    assert(read(fd, in, size) == size);
    assert(*in == c[i]);
  
    assert(read(fd, in, size) == size);
    assert(*in == c[i]);
    free(in);
  }
}

static void test_u_char_w(int fd, enum arch from, enum arch to) {
  unsigned char c[] = {0xF1, 0x02};
  int csize = sizeof(c) / sizeof(unsigned char);
  unsigned char *out;
  int ret, i;
  int size = aconv_char_size(from, to);
  assert(size == 1);
  for(i = 0; i < csize; i++) {
	  assert((out = malloc(size)) != NULL);
	  ret = aconv_u_char(&c[i], from, to, out);
	  if(from == to) {
	    assert(ret == ACONV_UNNEC);
      memcpy(out, &c[i], size);
    } else
	    assert(ret == ACONV_OK);
	  assert(write(fd, out, size) == size);
	  free(out);
	  
	  ret = aconv_u_char(&c[i], from, to, NULL);
	  if(from == to)
	    assert(ret == ACONV_UNNEC);
	  else
	    assert(ret == ACONV_OK);
	  assert(write(fd, &c[i], size) == size);
  }
}

static void test_u_char_r(int fd, enum arch from, enum arch to) {
  int i, size = sizeof(unsigned char);
  unsigned char *in;
  unsigned char c[] = {0xF1, 0x02};
  int csize = sizeof(c) / sizeof(unsigned char);
  assert(size == 1);
  for(i = 0; i < csize; i++) {
    assert((in = malloc(size)) != NULL);
    assert(read(fd, in, size) == size);
    assert(*in == c[i]);
  
    assert(read(fd, in, size) == size);
    assert(*in == c[i]);
    free(in);
  }
}

static void test_short_w(int fd, enum arch from, enum arch to) {
  int ret, i;
  short num[] = {0x0012, 0xFFAB };
  int num_size = sizeof(num) / sizeof(short);
  int size = aconv_short_size(from, to);
  short *out;
  assert(size == 2);
  for(i = 0; i < num_size; i++) {
	  assert((out = malloc(size)) != NULL);
	  ret = aconv_short(&num[i], from, to, out);
	  if(from == to) {
	    assert(ret == ACONV_UNNEC);
      memcpy(out, &num[i], size);
    } else
	    assert(ret == ACONV_OK);

	  assert(write(fd, out, size) == size);
	  free(out);
	  
	  ret = aconv_short(&num[i], from, to, NULL);
	  if(from != to) 
	    assert(ret == ACONV_OK);
	  else
	    assert(ret == ACONV_UNNEC);
	  assert(write(fd, &num[i], size) == size);
  }
}

static void test_short_r(int fd, enum arch from, enum arch to) {
  int i, size = sizeof(short);
  short *in;
  short num[] = {0x0012, 0xFFAB };
  int num_size = sizeof(num) / sizeof(short);
  assert(size == 2);
  for(i = 0; i < num_size; i++) {
    assert((in = malloc(size)) != NULL);
    assert(read(fd, in, size) == size);
    assert(*in == num[i]);
  
    assert(read(fd, in, size) == size);
    assert(*in == num[i]);
    free(in);
  }
}

static void test_u_short_w(int fd, enum arch from, enum arch to) {
  int ret, i;
  unsigned short num[] = {0x0012, 0xFFAB };
  int num_size = sizeof(num) / sizeof(unsigned short);
  int size = aconv_u_short_size(from, to);
  unsigned short *out;
  assert(size == 2);
  for(i = 0; i < num_size; i++) {
	  assert((out = malloc(size)) != NULL);
	  ret = aconv_u_short(&num[i], from, to, out);
	  if(from == to) {
	    assert(ret == ACONV_UNNEC);
      memcpy(out, &num[i], size);
    } else
	    assert(ret == ACONV_OK);
	  assert(write(fd, out, size) == size);
	  free(out);
	  
	  ret = aconv_u_short(&num[i], from, to, NULL);
	  if(from != to) 
	    assert(ret == ACONV_OK);
	  else
	    assert(ret == ACONV_UNNEC);
	  assert(write(fd, &num[i], size) == size);
  }
}

static void test_u_short_r(int fd, enum arch from, enum arch to) {
  int i, size = sizeof(unsigned short);
  unsigned short *in;
  unsigned short num[] = {0x0012, 0xFFAB };
  int num_size = sizeof(num) / sizeof(unsigned short);
  assert(size == 2);
  for(i = 0; i < num_size; i++) {
    assert((in = malloc(size)) != NULL);
    assert(read(fd, in, size) == size);
    assert(*in == num[i]);
  
    assert(read(fd, in, size) == size);
    assert(*in == num[i]);
    free(in);
  }
}

static void test_int_w(int fd, enum arch from, enum arch to) {
  int ret, i;
  int num[] = {0x00123456, 0xFF90ABCD };
  int num_size = sizeof(num) / sizeof(int);
  int size = aconv_int_size(from, to);
  int *out;
  assert(size == 4);
  for(i = 0; i < num_size; i++) {
	  assert((out = malloc(size)) != NULL);
	  ret = aconv_int(&num[i], from, to, out);
	  if(from == to) {
	    assert(ret == ACONV_UNNEC);
      memcpy(out, &num[i], size);
    } else
	    assert(ret == ACONV_OK);
	  assert(write(fd, out, size) == size);
	  free(out);
	  
	  ret = aconv_int(&num[i], from, to, NULL);
	  if(from != to) 
	    assert(ret == ACONV_OK);
	  else
	    assert(ret == ACONV_UNNEC);
	  assert(write(fd, &num[i], size) == size);
  }
}

static void test_int_r(int fd, enum arch from, enum arch to) {
  int size = sizeof(int);
  int *in, i;
  int num[] = {0x00123456, 0xFF90ABCD };
  int num_size = sizeof(num) / sizeof(int);
  assert(size == 4);
  for(i = 0; i < num_size; i++) {
    assert((in = malloc(size)) != NULL);
    assert(read(fd, in, size) == size);
    assert(*in == num[i]);
  
    assert(read(fd, in, size) == size);
    assert(*in == num[i]);
    free(in);
  }
}

static void test_u_int_w(int fd, enum arch from, enum arch to) {
  int ret, i;
  unsigned int num[] = {0x00123456, 0xFF90ABCD };
  int num_size = sizeof(num) / sizeof(unsigned int);
  int size = aconv_u_int_size(from, to);
  unsigned int *out;
  assert(size == 4);
  for(i = 0; i < num_size; i++) {
	  assert((out = malloc(size)) != NULL);
	  ret = aconv_u_int(&num[i], from, to, out);
	  if(from == to) {
	    assert(ret == ACONV_UNNEC);
      memcpy(out, &num[i], size);
    } else
	    assert(ret == ACONV_OK);
	  assert(write(fd, out, size) == size);
	  free(out);
	  
	  ret = aconv_u_int(&num[i], from, to, NULL);
	  if(from != to) 
	    assert(ret == ACONV_OK);
	  else
	    assert(ret == ACONV_UNNEC);
	  assert(write(fd, &num[i], size) == size);
  }
}

static void test_u_int_r(int fd, enum arch from, enum arch to) {
  int size = sizeof(unsigned int);
  int *in, i;
  unsigned int num[] = {0x00123456, 0xFF90ABCD };
  unsigned int num_size = sizeof(num) / sizeof(unsigned int);
  assert(size == 4);
  for(i = 0; i < num_size; i++) {
    assert((in = malloc(size)) != NULL);
    assert(read(fd, in, size) == size);
    assert(*in == num[i]);
  
    assert(read(fd, in, size) == size);
    assert(*in == num[i]);
    free(in);
  }
}
static void test_long_w(int fd, enum arch from, enum arch to) {
  int ret, n;
# if __WORDSIZE == 64
  /* positive and negative longs */
  long num[] = { 0x0011A67890ABCDEF, 0xFF22B67890ABCDEF, 
      171 /* 0x00000000000000AB*/, -51 /* 0xFFFFFFFFFFFFFFCD */ };
# else
  long num[] = { 0x0011A678, 0xFF22B678, 
    171 /* 0x000000AB */, -51 /* 0xFFFFFFCD */};
#endif
  int num_size = sizeof(num) / sizeof(long);
  int size = aconv_long_size(from, to);
  long *out;
  int from_bn, to_bn, i;
  from_bn = from & ACONV_BITNUM_MASK;
  to_bn = to & ACONV_BITNUM_MASK;
  if(from_bn == to_bn)
    if(from_bn == ACONV_64BIT)
      assert(size == 8);
    else
      assert(size == 4);
  else if(from_bn == ACONV_32BIT && to_bn == ACONV_64BIT)
    assert(size == 8);
  else
    assert(size == 4);

  for(i = 0; i < num_size; i++) {
	  assert((out = malloc(size)) != NULL);
	  ret = aconv_long(&num[i], from, to, out);
    if(from == to) {
      assert(ret == ACONV_UNNEC);
      /* If the conversion isn't necessary, the data isn't copied to 'out',
       * so I do it */ 
      memcpy(out, &num[i], size);
    } else
	    assert(ret == ACONV_OK);
	  n = write(fd, out, size);
	  assert(n == size);
	  free(out);
	
#if 0
	  ret = aconv_long(&num[i], from, to, NULL);
	  if((from & ACONV_BITNUM_MASK) != (to & ACONV_BITNUM_MASK)) {
	    assert(ret == ACONV_ERROR);
    } else {
      if(from == to)
	      assert(ret == ACONV_UNNEC);
	    else
	      assert(ret == ACONV_OK);
	    n = write(fd, &num[i], size);
	    assert(n == size);
    }
#endif
  }
}

static void test_long_r(int fd, enum arch from, enum arch to) {
  int i, size = sizeof(long);
  long *in;
  int from_bn, to_bn, num_size;
# if __WORDSIZE == 64
  long num[] = { 0x0011A67890ABCDEF, 0xFF22B67890ABCDEF, 
      171 /* 0x00000000000000AB*/, -51 /* 0xFFFFFFFFFFFFFFCD */ };
  assert(size == 8);
# else
  long num[] = { 0x0011A678, 0xFF22B678, 
    171 /* 0x000000AB */, -51 /* 0xFFFFFFCD */};
  assert(size == 4);
# endif
  num_size = sizeof(num) / sizeof(long);
	from_bn = from & ACONV_BITNUM_MASK;
	to_bn = to & ACONV_BITNUM_MASK;
  for(i = 0; i < num_size; i++) {
	    assert((in = malloc(size)) != NULL);
	    assert(read(fd, in, size) == size);
	    /* Same arch or same bit number */
		  if(from == to || from_bn == to_bn) {
		    assert(*in == num[i]);
	    /* 32 => 64 */
		  } else if(from_bn == ACONV_32BIT && to_bn == ACONV_64BIT) {
	# if __WORDSIZE == 64
	      switch(i) {
	        case 0:
		        assert(*in == 0x000000000011A678); break;
	        case 1:
		        assert(*in == 0xFFFFFFFFFF22B678); break;
	        case 2:
		        assert(*in == 171); break;
	        case 3:
		        assert(*in == -51); break;
	      }
	# endif
	    /* 64 => 32 */
		  } else if(from_bn == ACONV_64BIT && to_bn == ACONV_32BIT) {
	      switch(i) {
	        case 0:
		        assert(*in == INT_MAX); break;
	        case 1:
		        assert(*in == INT_MIN); break;
	        case 2:
		        assert(*in == 171); break;
	        case 3:
		        assert(*in == -51); break;
	      }
		  } else {
	      assert(0);
	    }
		  free(in);
  }
}

static void test_u_long_w(int fd, enum arch from, enum arch to) {
  int ret, n;
# if __WORDSIZE == 64
  /* positive and negative longs */
  unsigned long num[] = { 0x0011A67890ABCDEF, 0xFF22B67890ABCDEF, 
      171 /* 0x00000000000000AB*/};
# else
  unsigned long num[] = { 0x0011A678, 0xFF22B678, 171 /* 0x000000AB */};
#endif
  int num_size = sizeof(num) / sizeof(unsigned long);
  int size = aconv_u_long_size(from, to);
  unsigned long *out;
  int from_bn, to_bn, i;
  from_bn = from & ACONV_BITNUM_MASK;
  to_bn = to & ACONV_BITNUM_MASK;
  if(from_bn == to_bn)
    if(from_bn == ACONV_64BIT)
      assert(size == 8);
    else
      assert(size == 4);
  else if(from_bn == ACONV_32BIT && to_bn == ACONV_64BIT)
    assert(size == 8);
  else
    assert(size == 4);

  for(i = 0; i < num_size; i++) {
	  assert((out = malloc(size)) != NULL);
	  ret = aconv_u_long(&num[i], from, to, out);
    if(from == to) {
      assert(ret == ACONV_UNNEC);
      /* If the conversion isn't necessary, the data isn't copied to 'out',
       * so I do it */ 
      memcpy(out, &num[i], size);
    } else
	    assert(ret == ACONV_OK);
	  n = write(fd, out, size);
	  assert(n == size);
	  free(out);
	
#if 0
	  ret = aconv_u_long(&num[i], from, to, NULL);
	  if((from & ACONV_BITNUM_MASK) != (to & ACONV_BITNUM_MASK)) {
	    assert(ret == ACONV_ERROR);
    } else {
      if(from == to)
	      assert(ret == ACONV_UNNEC);
	    else
	      assert(ret == ACONV_OK);
	    n = write(fd, &num[i], size);
	    assert(n == size);
    }
#endif
  }
}

static void test_u_long_r(int fd, enum arch from, enum arch to) {
  int i, size = sizeof(unsigned long);
  unsigned long *in;
  int from_bn, to_bn, num_size;
# if __WORDSIZE == 64
  unsigned long num[] = { 0x0011A67890ABCDEF, 0xFF22B67890ABCDEF, 
      171 /* 0x00000000000000AB*/};
  assert(size == 8);
# else
  unsigned long num[] = { 0x0011A678, 0xFF22B678, 171 /* 0x000000AB */};
  assert(size == 4);
# endif
  num_size = sizeof(num) / sizeof(unsigned long);
	from_bn = from & ACONV_BITNUM_MASK;
	to_bn = to & ACONV_BITNUM_MASK;
  for(i = 0; i < num_size; i++) {
	    assert((in = malloc(size)) != NULL);
	    assert(read(fd, in, size) == size);
	    /* Same arch or same bit number */
		  if(from == to || from_bn == to_bn) {
		    assert(*in == num[i]);
	    /* 32 => 64 */
		  } else if(from_bn == ACONV_32BIT && to_bn == ACONV_64BIT) {
	# if __WORDSIZE == 64
	      switch(i) {
	        case 0:
		        assert(*in == 0x000000000011A678); break;
	        case 1:
		        assert(*in == 0x00000000FF22B678); break;
	        case 2:
		        assert(*in == 171); break;
	      }
	# endif
	    /* 64 => 32 */
		  } else if(from_bn == ACONV_64BIT && to_bn == ACONV_32BIT) {
	      switch(i) {
	        case 0:
		        assert(*in == UINT_MAX); break;
	        case 1:
		        assert(*in == UINT_MAX); break;
	        case 2:
		        assert(*in == 171); break;
	      }
		  } else {
	      assert(0);
	    }
		  free(in);
  }
}

static void test_longlong_w(int fd, enum arch from, enum arch to) {
  int ret, i;
  long long  num[] = {0x000000ABCDEF1234LL, 0xFFFF567890BBBBBBLL };
  int num_size = sizeof(num) / sizeof(long long);
  int size = aconv_longlong_size(from, to);
  long long *out;
  assert(size == 8);
  for(i = 0; i < num_size; i++) {
	  assert((out = malloc(size)) != NULL);
	  ret = aconv_longlong(&num[i], from, to, out);
	  if(from == to) {
	    assert(ret == ACONV_UNNEC);
      memcpy(out, &num[i], size);
    } else
	    assert(ret == ACONV_OK);
	  assert(write(fd, out, size) == size);
	  free(out);
	  
	  ret = aconv_longlong(&num[i], from, to, NULL);
	  if(from != to) 
	    assert(ret == ACONV_OK);
	  else
	    assert(ret == ACONV_UNNEC);
	  assert(write(fd, &num[i], size) == size);
  }
}

static void test_longlong_r(int fd, enum arch from, enum arch to) {
  int i, size = sizeof(long long);
  long long *in;
  long long  num[] = {0x000000ABCDEF1234LL, 0xFFFF567890BBBBBBLL };
  int num_size = sizeof(num) / sizeof(long long);
  assert(size == 8);
  for(i = 0; i < num_size; i++) {
    assert((in = malloc(size)) != NULL);
    assert(read(fd, in, size) == size);
    assert(*in == num[i]);
  
    assert(read(fd, in, size) == size);
    assert(*in == num[i]);
    free(in);
  }
}

static void test_u_longlong_w(int fd, enum arch from, enum arch to) {
  int ret, i;
  unsigned long long  num[] = {0x000000ABCDEF1234ULL, 0xFFFF567890BBBBBBULL };
  int num_size = sizeof(num) / sizeof(unsigned long long);
  int size = aconv_u_longlong_size(from, to);
  unsigned long long *out;
  assert(size == 8);
  for(i = 0; i < num_size; i++) {
	  assert((out = malloc(size)) != NULL);
	  ret = aconv_u_longlong(&num[i], from, to, out);
	  if(from == to) {
	    assert(ret == ACONV_UNNEC);
      memcpy(out, &num[i], size);
    } else
	    assert(ret == ACONV_OK);
	  assert(write(fd, out, size) == size);
	  free(out);
	  
	  ret = aconv_u_longlong(&num[i], from, to, NULL);
	  if(from != to) 
	    assert(ret == ACONV_OK);
	  else
	    assert(ret == ACONV_UNNEC);
	  assert(write(fd, &num[i], size) == size);
  }
}

static void test_u_longlong_r(int fd, enum arch from, enum arch to) {
  int i, size = sizeof(unsigned long long);
  unsigned long long *in;
  unsigned long long  num[] = {0x000000ABCDEF1234ULL, 0xFFFF567890BBBBBBULL };
  int num_size = sizeof(num) / sizeof(unsigned long long);
  assert(size == 8);
  for(i = 0; i < num_size; i++) {
    assert((in = malloc(size)) != NULL);
    assert(read(fd, in, size) == size);
    assert(*in == num[i]);
  
    assert(read(fd, in, size) == size);
    assert(*in == num[i]);
    free(in);
  }
}

static void test_pointer_w(int fd, enum arch from, enum arch to) {
  int i, ret, a, b;
  int from_bn, to_bn;
#if __WORDSIZE == 64
  int *ps[] = { &a, NULL, &b, (int *)0x0000000012345678, (int *)0x99ABCDEF00000000};
#else
  int *ps[] = { &a, NULL, &b, (int *)0x12345678, (int *)0x99ABCDEF};
#endif
  int ps_size = sizeof(ps) / sizeof(long);
  int size = aconv_pointer_size(from, to);
  int **out;

  from_bn = from & ACONV_BITNUM_MASK;
  to_bn = to & ACONV_BITNUM_MASK;
  if(to_bn == ACONV_64BIT)
    assert(size == 8);
  else
    assert(size == 4);
  for(i = 0; i < ps_size; i++) {
    assert((out = malloc(size)) != NULL);
    ret = aconv_pointer(ps[i], from, to, out);
    if(from == to || from_bn == to_bn) {
      /* assert(ret == ACONV_UNNEC); */
      memcpy(out, &ps[i], size);
    } else
      assert(ret == ACONV_OK);

    assert(write(fd, out, size) == size);
    free(out);
  }
}

static void test_pointer_r(int fd, enum arch from, enum arch to) {
  int from_bn, to_bn, i, a, b;
  int **c;
#if __WORDSIZE == 64
  int *ps[] = { &a, NULL, &b, (int *)0x0000000012345678, (int *)0x99ABCDEF00000000};
#else
  int *ps[] = { &a, NULL, &b, (int *)0x12345678, (int *)0x99ABCDEF};
#endif
  int ps_size = sizeof(ps) / sizeof(long);
  int *in;
  int size = sizeof(long *);

  from_bn = from & ACONV_BITNUM_MASK;
  to_bn = to & ACONV_BITNUM_MASK;
  for(i = 0; i < ps_size; i++) {
    assert(read(fd, &in, size) == size);
    if(ps[i] != NULL)
      assert(in != NULL);
    else
      assert(in == NULL);
  }
}

static void test_string_w(int fd, enum arch from, enum arch to) {
  int ret, i;
  char *str[] = {"", "Hello world!!!" };
  int str_size = sizeof(str) / sizeof(char *);
  char *out;
  for(i = 0; i < str_size; i++) {
    int size = aconv_string_size(str[i], from, to);
    assert(size == strlen(str[i]) + 1);
	  assert((out = malloc(size)) != NULL);
	  ret = aconv_string(str[i], from, to, out);
	  if(from == to) {
	    assert(ret == ACONV_UNNEC);
      memcpy(out, str[i], size);
    } else
	    assert(ret == ACONV_OK);
	  assert(write(fd, out, size) == size);
	  free(out);
	  
	  ret = aconv_string(str[i], from, to, NULL);
	  if(from != to) 
	    assert(ret == ACONV_OK);
	  else
	    assert(ret == ACONV_UNNEC);
	  assert(write(fd, str[i], size) == size);
  }
}

static void test_string_r(int fd, enum arch from, enum arch to) {
  char *in;
  char *str[] = {"", "Hello world!!!" };
  int i, str_size = sizeof(str) / sizeof(char *);
  for(i = 0; i < str_size; i++) {
    int size = strlen(str[i]) + 1;
    assert((in = malloc(size)) != NULL);
    assert(read(fd, in, size) == size);
    assert(strcmp(str[i], in) == 0);
  
    assert(read(fd, in, size) == size);
    assert(strcmp(str[i], in) == 0);
    free(in);
  }
}

static void test_mode_t_w(int fd, enum arch from, enum arch to) {
  int ret, i;
  mode_t  num[] = {0xFF123456, 0x0000ABCD };
  int num_size = sizeof(num) / sizeof(mode_t);
  int size = aconv_mode_t_size(from, to);
  mode_t *out;
  assert(size == sizeof(mode_t));
  for(i = 0; i < num_size; i++) {
	  assert((out = malloc(size)) != NULL);
	  ret = aconv_mode_t(&num[i], from, to, out);
	  if(from == to) {
	    assert(ret == ACONV_UNNEC);
      memcpy(out, &num[i], size);
    } else
	    assert(ret == ACONV_OK);
	  assert(write(fd, out, size) == size);
	  free(out);
	  
	  ret = aconv_mode_t(&num[i], from, to, NULL);
	  if(from != to) 
	    assert(ret == ACONV_OK);
	  else
	    assert(ret == ACONV_UNNEC);
	  assert(write(fd, &num[i], size) == size);
  }
}
static void test_mode_t_r(int fd, enum arch from, enum arch to) {
  int i, size = sizeof(mode_t);
  mode_t *in;
  mode_t num[] = {0xFF123456, 0x0000ABCD };
  int num_size = sizeof(num) / sizeof(mode_t);
  assert(sizeof(mode_t) == 4);

  for(i = 0; i < num_size; i++) {
    assert((in = malloc(size)) != NULL);
    assert(read(fd, in, size) == size);
    assert(*in == num[i]);
  
    assert(read(fd, in, size) == size);
    assert(*in == num[i]);
    free(in);
  }
}

static void test_loff_t_w(int fd, enum arch from, enum arch to) {
  int ret, i;
  loff_t  num[] = {0xFFFFFFAB123456LL, 0x000000ABCDEF9087LL };
  int num_size = sizeof(num) / sizeof(loff_t);
  int size = aconv_loff_t_size(from, to);
  loff_t *out;
  assert(size == sizeof(loff_t));
  for(i = 0; i < num_size; i++) {
	  assert((out = malloc(size)) != NULL);
	  ret = aconv_loff_t(&num[i], from, to, out);
	  if(from == to) {
	    assert(ret == ACONV_UNNEC);
      memcpy(out, &num[i], size);
    } else
	    assert(ret == ACONV_OK);
	  assert(write(fd, out, size) == size);
	  free(out);
	  
	  ret = aconv_loff_t(&num[i], from, to, NULL);
	  if(from != to) 
	    assert(ret == ACONV_OK);
	  else
	    assert(ret == ACONV_UNNEC);
	  assert(write(fd, &num[i], size) == size);
  }
}
static void test_loff_t_r(int fd, enum arch from, enum arch to) {
  int i, size = sizeof(loff_t);
  loff_t *in;
  loff_t  num[] = {0xFFFFFFAB123456LL, 0x000000ABCDEF9087LL };
  int num_size = sizeof(num) / sizeof(loff_t);
  assert(sizeof(loff_t) == 8);

  for(i = 0; i < num_size; i++) {
    assert((in = malloc(size)) != NULL);
    assert(read(fd, in, size) == size);
    assert(*in == num[i]);
  
    assert(read(fd, in, size) == size);
    assert(*in == num[i]);
    free(in);
  }
}

static void test_uid_t_w(int fd, enum arch from, enum arch to) {
  int ret, i;
  uid_t  num[] = {0xFF123456, 0x0000ABCD };
  int num_size = sizeof(num) / sizeof(uid_t);
  int size = aconv_uid_t_size(from, to);
  uid_t *out;
  assert(size == sizeof(uid_t));
  for(i = 0; i < num_size; i++) {
	  assert((out = malloc(size)) != NULL);
	  ret = aconv_uid_t(&num[i], from, to, out);
	  if(from == to) {
	    assert(ret == ACONV_UNNEC);
      memcpy(out, &num[i], size);
    } else
	    assert(ret == ACONV_OK);
	  assert(write(fd, out, size) == size);
	  free(out);
	  
	  ret = aconv_uid_t(&num[i], from, to, NULL);
	  if(from != to) 
	    assert(ret == ACONV_OK);
	  else
	    assert(ret == ACONV_UNNEC);
	  assert(write(fd, &num[i], size) == size);
  }
}
static void test_uid_t_r(int fd, enum arch from, enum arch to) {
  int i, size = sizeof(uid_t);
  uid_t *in;
  uid_t num[] = {0xFF123456, 0x0000ABCD };
  int num_size = sizeof(num) / sizeof(uid_t);
  assert(sizeof(uid_t) == 4);

  for(i = 0; i < num_size; i++) {
    assert((in = malloc(size)) != NULL);
    assert(read(fd, in, size) == size);
    assert(*in == num[i]);
  
    assert(read(fd, in, size) == size);
    assert(*in == num[i]);
    free(in);
  }
}

static void test_gid_t_w(int fd, enum arch from, enum arch to) {
  int ret, i;
  gid_t  num[] = {0xFF123456, 0x0000ABCD };
  int num_size = sizeof(num) / sizeof(gid_t);
  int size = aconv_gid_t_size(from, to);
  gid_t *out;
  assert(size == sizeof(gid_t));
  for(i = 0; i < num_size; i++) {
	  assert((out = malloc(size)) != NULL);
	  ret = aconv_gid_t(&num[i], from, to, out);
	  if(from == to) {
	    assert(ret == ACONV_UNNEC);
      memcpy(out, &num[i], size);
    } else
	    assert(ret == ACONV_OK);
	  assert(write(fd, out, size) == size);
	  free(out);
	  
	  ret = aconv_gid_t(&num[i], from, to, NULL);
	  if(from != to) 
	    assert(ret == ACONV_OK);
	  else
	    assert(ret == ACONV_UNNEC);
	  assert(write(fd, &num[i], size) == size);
  }
}
static void test_gid_t_r(int fd, enum arch from, enum arch to) {
  int i, size = sizeof(gid_t);
  gid_t *in;
  gid_t num[] = {0xFF123456, 0x0000ABCD };
  int num_size = sizeof(num) / sizeof(gid_t);
  assert(sizeof(gid_t) == 4);

  for(i = 0; i < num_size; i++) {
    assert((in = malloc(size)) != NULL);
    assert(read(fd, in, size) == size);
    assert(*in == num[i]);
  
    assert(read(fd, in, size) == size);
    assert(*in == num[i]);
    free(in);
  }
}

static void test_clockid_t_w(int fd, enum arch from, enum arch to) {
  int ret, i;
  clockid_t  num[] = {0xFF123456, 0x0000ABCD };
  int num_size = sizeof(num) / sizeof(clockid_t);
  int size = aconv_clockid_t_size(from, to);
  clockid_t *out;
  assert(size == sizeof(clockid_t));
  for(i = 0; i < num_size; i++) {
	  assert((out = malloc(size)) != NULL);
	  ret = aconv_clockid_t(&num[i], from, to, out);
	  if(from == to) {
	    assert(ret == ACONV_UNNEC);
      memcpy(out, &num[i], size);
    } else
	    assert(ret == ACONV_OK);
	  assert(write(fd, out, size) == size);
	  free(out);
	  
	  ret = aconv_clockid_t(&num[i], from, to, NULL);
	  if(from != to) 
	    assert(ret == ACONV_OK);
	  else
	    assert(ret == ACONV_UNNEC);
	  assert(write(fd, &num[i], size) == size);
  }
}
static void test_clockid_t_r(int fd, enum arch from, enum arch to) {
  int i, size = sizeof(clockid_t);
  clockid_t *in;
  clockid_t num[] = {0xFF123456, 0x0000ABCD };
  int num_size = sizeof(num) / sizeof(clockid_t);
  assert(sizeof(clockid_t) == 4);

  for(i = 0; i < num_size; i++) {
    assert((in = malloc(size)) != NULL);
    assert(read(fd, in, size) == size);
    assert(*in == num[i]);
  
    assert(read(fd, in, size) == size);
    assert(*in == num[i]);
    free(in);
  }
}

static void test___off64_t_w(int fd, enum arch from, enum arch to) {
  int ret, i;
  __off64_t  num[] = {0xFFFFFFAB123456LL, 0x000000ABCDEF9087LL };
  int num_size = sizeof(num) / sizeof(__off64_t);
  int size = aconv___off64_t_size(from, to);
  __off64_t *out;
  assert(size == sizeof(__off64_t));
  for(i = 0; i < num_size; i++) {
	  assert((out = malloc(size)) != NULL);
	  ret = aconv___off64_t(&num[i], from, to, out);
	  if(from == to) {
	    assert(ret == ACONV_UNNEC);
      memcpy(out, &num[i], size);
    } else
	    assert(ret == ACONV_OK);
	  assert(write(fd, out, size) == size);
	  free(out);
	  
	  ret = aconv___off64_t(&num[i], from, to, NULL);
	  if(from != to) 
	    assert(ret == ACONV_OK);
	  else
	    assert(ret == ACONV_UNNEC);
	  assert(write(fd, &num[i], size) == size);
  }
}
static void test___off64_t_r(int fd, enum arch from, enum arch to) {
  int i, size = sizeof(__off64_t);
  __off64_t *in;
  __off64_t  num[] = {0xFFFFFFAB123456LL, 0x000000ABCDEF9087LL };
  int num_size = sizeof(num) / sizeof(__off64_t);
  assert(sizeof(__off64_t) == 8);

  for(i = 0; i < num_size; i++) {
    assert((in = malloc(size)) != NULL);
    assert(read(fd, in, size) == size);
    assert(*in == num[i]);
  
    assert(read(fd, in, size) == size);
    assert(*in == num[i]);
    free(in);
  }
}

static void test_socklen_t_w(int fd, enum arch from, enum arch to) {
  int ret, i;
  socklen_t  num[] = {0xFF123456, 0x0000ABCD };
  int num_size = sizeof(num) / sizeof(socklen_t);
  int size = aconv_socklen_t_size(from, to);
  socklen_t *out;
  assert(size == sizeof(socklen_t));
  for(i = 0; i < num_size; i++) {
	  assert((out = malloc(size)) != NULL);
	  ret = aconv_socklen_t(&num[i], from, to, out);
	  if(from == to) {
	    assert(ret == ACONV_UNNEC);
      memcpy(out, &num[i], size);
    } else
	    assert(ret == ACONV_OK);
	  assert(write(fd, out, size) == size);
	  free(out);
	  
	  ret = aconv_socklen_t(&num[i], from, to, NULL);
	  if(from != to) 
	    assert(ret == ACONV_OK);
	  else
	    assert(ret == ACONV_UNNEC);
	  assert(write(fd, &num[i], size) == size);
  }
}
static void test_socklen_t_r(int fd, enum arch from, enum arch to) {
  int i, size = sizeof(socklen_t);
  socklen_t *in;
  socklen_t num[] = {0xFF123456, 0x0000ABCD };
  int num_size = sizeof(num) / sizeof(socklen_t);
  assert(sizeof(socklen_t) == 4);

  for(i = 0; i < num_size; i++) {
    assert((in = malloc(size)) != NULL);
    assert(read(fd, in, size) == size);
    assert(*in == num[i]);
  
    assert(read(fd, in, size) == size);
    assert(*in == num[i]);
    free(in);
  }
}

static void test_size_t_w(int fd, enum arch from, enum arch to) {
  int from_bn, to_bn, ret, i;
  int size = aconv_size_t_size(from, to);
#if __WORDSIZE == 64
  size_t  num[] = {0xFF1234567890ABCD, 0x00ABCDEF12345678,  0xFF123456, 0x0000ABCD};
#else
  size_t  num[] = {0xFFFFFFFF, 0xFFFFFFFF,  0xFF123456, 0x0000ABCD };
#endif
  int num_size  = sizeof(num) / sizeof(size_t);
  size_t *out;
  from_bn = from & ACONV_BITNUM_MASK;
  to_bn   = to & ACONV_BITNUM_MASK;
  if(to_bn == ACONV_32BIT)
    assert(size == 4);
  else
    assert(size == 8);
  for(i = 0; i < num_size; i++) {
    assert((out = malloc(size)) != NULL);
    ret = aconv_size_t(&num[i], from, to, out);
    if(from == to) {
      assert(ret == ACONV_UNNEC);
      memcpy(out, &num[i], size);
    } else
      assert(ret == ACONV_OK);
    assert(write(fd, out, size) == size);

    if(from_bn == to_bn) {
      ret = aconv_size_t(&num[i], from, to, NULL);
      if(from == to) 
        assert(ret == ACONV_UNNEC);
      else
        assert(ret == ACONV_OK);
      assert(write(fd, &num[i], size) == size);
    }
    free(out);
  }
 

}
static void test_size_t_r(int fd, enum arch from, enum arch to) {
  int i, from_bn, to_bn;
  int size = sizeof(size_t);
  size_t in;
  unsigned long  num32to32[] = {0xFFFFFFFF, 0xFFFFFFFF,  0xFF123456, 0x0000ABCD };
  unsigned long long num64to64[] = {0xFF1234567890ABCDULL, 0x00ABCDEF12345678ULL,  0xFF123456ULL, 0x0000ABCDULL};
  unsigned long long num32to64[] = {0x00000000FFFFFFFFULL, 0x00000000FFFFFFFFULL, 0x00000000FF123456ULL, 0x000000000000ABCDULL };
  unsigned long  num64to32[] = {0xFFFFFFFF, 0xFFFFFFFF,  0xFF123456, 0x0000ABCD };
  from_bn = from & ACONV_BITNUM_MASK;
  to_bn   = to & ACONV_BITNUM_MASK;
  for(i = 0; i < 4; i++) {
    assert(read(fd, &in, size) == size);
    if(from_bn == to_bn) {
      if(from_bn == ACONV_32BIT)
        assert(in == num32to32[i]);
      else 
        assert(in == num64to64[i]);
    } else if(from_bn == ACONV_32BIT && to_bn == ACONV_64BIT) {
      assert(in == num32to64[i]);
    } else if(from_bn == ACONV_64BIT && to_bn == ACONV_32BIT) {
      assert(in == num64to32[i]);
    }

    if(from_bn == to_bn) {
      assert(read(fd, &in, size) == size);
      if(from_bn == ACONV_64BIT)
        assert(in == num64to64[i]);
      else
        assert(in == num32to32[i]);
    }
  }
}


static void test_off_t_w(int fd, enum arch from, enum arch to) {
  int from_bn, to_bn, ret, i;
  int size = aconv_off_t_size(from, to);
#if __WORDSIZE == 64
  off_t  num[] = {0xFF1234567890ABCD, 0x00ABCDEF12345678,  0xFF123456, 0x0000ABCD};
#else
  off_t  num[] = {0xFFFFFFFF, 0xFFFFFFFF,  0xFF123456, 0x0000ABCD };
#endif
  int num_size  = sizeof(num) / sizeof(off_t);
  off_t *out;
  from_bn = from & ACONV_BITNUM_MASK;
  to_bn   = to & ACONV_BITNUM_MASK;
  if(to_bn == ACONV_32BIT)
    assert(size == 4);
  else
    assert(size == 8);
  for(i = 0; i < num_size; i++) {
    assert((out = malloc(size)) != NULL);
    ret = aconv_off_t(&num[i], from, to, out);
    if(from == to) {
      assert(ret == ACONV_UNNEC);
      memcpy(out, &num[i], size);
    } else
      assert(ret == ACONV_OK);
    assert(write(fd, out, size) == size);

    if(from_bn == to_bn) {
      ret = aconv_off_t(&num[i], from, to, NULL);
      if(from == to) 
        assert(ret == ACONV_UNNEC);
      else
        assert(ret == ACONV_OK);
      assert(write(fd, &num[i], size) == size);
    }
    free(out);
  }
 

}
static void test_off_t_r(int fd, enum arch from, enum arch to) {
  int i, from_bn, to_bn;
  int size = sizeof(off_t);
  off_t in;
  unsigned long  num32to32[] = {0xFFFFFFFF, 0xFFFFFFFF,  0xFF123456, 0x0000ABCD };
  unsigned long long num64to64[] = {0xFF1234567890ABCDULL, 0x00ABCDEF12345678ULL,  0xFF123456ULL, 0x0000ABCDULL};
  unsigned long long num32to64[] = {0x00000000FFFFFFFFULL, 0x00000000FFFFFFFFULL, 0x00000000FF123456ULL, 0x000000000000ABCDULL };
  unsigned long  num64to32[] = {0xFFFFFFFF, 0xFFFFFFFF,  0xFF123456, 0x0000ABCD };
  from_bn = from & ACONV_BITNUM_MASK;
  to_bn   = to & ACONV_BITNUM_MASK;
  for(i = 0; i < 4; i++) {
    assert(read(fd, &in, size) == size);
    if(from_bn == to_bn) {
      if(from_bn == ACONV_32BIT)
        assert(in == num32to32[i]);
      else 
        assert(in == num64to64[i]);
    } else if(from_bn == ACONV_32BIT && to_bn == ACONV_64BIT) {
      assert(in == num32to64[i]);
    } else if(from_bn == ACONV_64BIT && to_bn == ACONV_32BIT) {
      assert(in == num64to32[i]);
    }

    if(from_bn == to_bn) {
      assert(read(fd, &in, size) == size);
      if(from_bn == ACONV_64BIT)
        assert(in == num64to64[i]);
      else
        assert(in == num32to32[i]);
    }
  }
}

static void test_array_w(int fd, enum arch from, enum arch to) {
  int ai[] = {1, 2, 3, 4, 5};
  long al[] = {0xAL, 0xBL, 0xCL, -42, 0xEL};
  long l0, l1, l2, l4;
  /* long *ap[] = {&l0, &l1, &l2, NULL, &l4}; */
  int *out;
  void *in;
  int ret, size, i;
  int from_bn, to_bn;
  aconv_size_fun sizef;
  aconv_fun aconvf;

	from_bn = from & ACONV_BITNUM_MASK;
	to_bn   = to & ACONV_BITNUM_MASK;
  for(i = 0; i < 2; i++) {
    switch(i) {
      case 0:
        sizef = aconv_int_size;
        aconvf = aconv_int;
        in = ai;
        break;
      case 1:
        sizef = aconv_long_size;
        aconvf = aconv_long;
        in = al;
        break;
      /* case 2: */
        /* sizef = aconv_pointer_size; */
        /* aconvf = aconv_pointer; */
        /* in = ap; */
        /* break; */
      default:
        assert(0);
        break;
    }
	  size = 5 * sizef(from, to);
	  out = malloc(size);
	  assert(out != NULL);
	  ret = aconv_array(in, from, to, 5, out, sizef, aconvf);
	  if(from == to) {
	    assert(ret == ACONV_UNNEC);
	    memcpy(out, in, size);
	  } else
	    assert(ret == ACONV_OK);
		assert(write(fd, out, size) == size);
	  free(out);
	
	  if(from_bn == to_bn) {
	    ret = aconv_array(in, from, to, 5, NULL, sizef, aconvf);
	    assert(ret == ACONV_OK || ret == ACONV_UNNEC);
		  assert(write(fd, in, size) == size);
	  }
  }
}

static void test_array_r(int fd, enum arch from, enum arch to) {
  int ai[] = {1, 2, 3, 4, 5};
  long al[] = {0xAL, 0xBL, 0xCL, -42, 0xEL};
  void *in;
  int size, i, j;
  int from_bn, to_bn;
  aconv_size_fun sizef;

  from_bn = from & ACONV_BITNUM_MASK;
  to_bn   = to & ACONV_BITNUM_MASK;

  for(j = 0; j < 2; j++) {
    switch(j) {
      case 0:
        sizef = aconv_int_size; break;
      case 1:
        sizef = aconv_long_size; break;
      /* case 2: */
        /* sizef = aconv_pointer_size; break; */
      default:
        assert(0); break;
    }
	  size = 5 * sizef(from, to);
	  in = malloc(size);
	  assert(in != NULL);
	  assert(read(fd, in, size) == size);
	  for(i = 0; i < 5; i++) {
      switch(j) {
        case 0:
	        assert(ai[i] == ((int *)in)[i]); break;
        case 1:
	        assert(al[i] == ((long *)in)[i]); break;
        case 2:
          if(i == 3)
	          assert(((long **)in)[i] == NULL); 
          else 
	          assert(((long **)in)[i] != NULL); 
          break;
        default:
          assert(0); break;
      }
	  }
	  free(in);
	  
	  if(from_bn == to_bn) {
	    size = 5 * sizef(from, to);
	    in = malloc(size);
	    assert(in != NULL);
	    assert(read(fd, in, size) == size);
	    for(i = 0; i < 5; i++) {
	      switch(j) {
          case 0:
	          assert(ai[i] == ((int *)in)[i]); break;
          case 1:
	          assert(al[i] == ((long *)in)[i]); break;
          case 2:
            if(i == 3)
	            assert(((long **)in)[i] == NULL); 
            else
	            assert(((long **)in)[i] != NULL); 
            break;
          default:
            assert(0); break;
        }
	    }
	    free(in);
	  }
  }
}

static void test_struct_dirent64_w(int fd, enum arch from, enum arch to) {
  struct dirent64 d;
  int size = aconv_struct_dirent64_size(from, to);
  int ret;
  void *out;
  d.d_ino = 0x1122334455667788;
  d.d_off = 0x9900AABBCCDDEEFF;
  d.d_reclen = 0x1234;
  d.d_type = 0xFF;
  bzero(d.d_name, 256);
  memset(d.d_name, 'b', 255);

  assert((out = malloc(size)) != NULL);
  ret = aconv_struct_dirent64(&d, from, to, out);
  assert(ret != ACONV_ERROR);
  if(from == to)
    memcpy(out, &d, size);
  assert(write(fd, out, size) == size);
  free(out);
}
static void test_struct_dirent64_r(int fd, enum arch from, enum arch to) {
  struct dirent64 d;
  int size = aconv_struct_dirent64_size(from, to);
  struct dirent64 *in;
  assert(size == sizeof(struct dirent64));
  d.d_ino = 0x1122334455667788;
  d.d_off = 0x9900AABBCCDDEEFF;
  d.d_reclen = 0x1234;
  d.d_type = 0xFF;
  bzero(d.d_name, 256);
  memset(d.d_name, 'b', 255);

  assert((in = malloc(size)) != NULL);
  assert(read(fd, in, size) == size);
  assert(d.d_ino == in->d_ino);
  assert(d.d_off == in->d_off);
  assert(d.d_reclen == in->d_reclen); 
  assert(d.d_type == in->d_type);
  assert(memcmp(d.d_name, in->d_name, 256) == 0);
  free(in);
}

static void test_struct_sockaddr_w(int fd, enum arch from, enum arch to) {
  struct sockaddr *s;
  int size = aconv_struct_sockaddr_size(from, to);
  int ret, i;
  void *out;

  for(i = 0; i < 2; i++) {
    assert((s = malloc(size)) != NULL);
    switch(i) {
      case 0:
	      s->sa_family = 0x11;
	      bzero(s->sa_data, 14);
	      memset(s->sa_data, 'b', 13);
        break;
      case 1: {
        struct sockaddr_in *sin = (struct sockaddr *)s;
        sin->sin_family = AF_INET;
        sin->sin_port = htons(0xAA);
        sin->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        break;
      } 
      default:
        assert(0);
        break;
    }
	  
	  assert((out = malloc(size)) != NULL);
	  ret = aconv_struct_sockaddr(s, from, to, out);
	  assert(ret != ACONV_ERROR);
	  if(from == to)
	    memcpy(out, s, size);
	  assert(write(fd, out, size) == size);
	  free(out); free(s);
  }
}
static void test_struct_sockaddr_r(int fd, enum arch from, enum arch to) {
  int size = aconv_struct_sockaddr_size(from, to);
  struct sockaddr *in;
  int i;

  for(i = 0; i < 2; i++) {
    assert((in = malloc(size)) != NULL);
    assert(read(fd, in, size) == size);
    switch(i) {
      case 0: {
        struct sockaddr e;
	      e.sa_family = 0x11;
	      bzero(e.sa_data, 14);
	      memset(e.sa_data, 'b', 13);

        assert(in->sa_family == e.sa_family);
        assert(memcmp(e.sa_data, in->sa_data, 14) == 0);
        break;
      }
      case 1: {
        struct sockaddr_in *sin = (struct sockaddr *)in;
        assert(sin->sin_family == AF_INET);
        assert(sin->sin_port == htons(0xAA));
        assert(sin->sin_addr.s_addr == htonl(INADDR_LOOPBACK));
        break;
      } 
      default:
        assert(0);
        break;
    }
	  
	  free(in);
  }
}

static void test_struct_timespec_w(int fd, enum arch from, enum arch to) {
  struct timespec t;
  int size = aconv_struct_timespec_size(from, to);
  int ret;
  void *out;
  t.tv_sec  = 0x12345678;
  t.tv_nsec = 0x09ABCDEF;
  
  assert((out = malloc(size)) != NULL);
  ret = aconv_struct_timespec(&t, from, to, out);
  assert(ret != ACONV_ERROR);
  if(from == to)
    memcpy(out, &t, size);
  assert(write(fd, out, size) == size);
  free(out);
}
static void test_struct_timespec_r(int fd, enum arch from, enum arch to) {
  struct timespec t;
  int size = aconv_struct_timespec_size(from, to);
  struct timespec *in;
  assert(size == sizeof(struct timespec));
  t.tv_sec  = 0x12345678;
  t.tv_nsec = 0x09ABCDEF;

  assert((in = malloc(size)) != NULL);
  assert(read(fd, in, size) == size);
  assert(t.tv_sec == in->tv_sec);
  assert(t.tv_nsec == in->tv_nsec);
  free(in);
}

static void test_struct_timeval_w(int fd, enum arch from, enum arch to) {
  struct timeval t;
  int size = aconv_struct_timeval_size(from, to);
  int ret;
  void *out;
  t.tv_sec  = 0x12345678;
  t.tv_usec = 0x09ABCDEF;
  
  assert((out = malloc(size)) != NULL);
  ret = aconv_struct_timeval(&t, from, to, out);
  assert(ret != ACONV_ERROR);
  if(from == to)
    memcpy(out, &t, size);
  assert(write(fd, out, size) == size);
  free(out);
}
static void test_struct_timeval_r(int fd, enum arch from, enum arch to) {
  struct timeval t;
  int size = aconv_struct_timeval_size(from, to);
  struct timeval *in;
  assert(size == sizeof(struct timeval));
  t.tv_sec  = 0x12345678;
  t.tv_usec = 0x09ABCDEF;

  assert((in = malloc(size)) != NULL);
  assert(read(fd, in, size) == size);
  assert(t.tv_sec == in->tv_sec);
  assert(t.tv_usec == in->tv_usec);
  free(in);
}
static void test_struct_timezone_w(int fd, enum arch from, enum arch to) {
  struct timezone t;
  int size = aconv_struct_timezone_size(from, to);
  int ret;
  void *out;
  t.tz_minuteswest = 0x12345678;
  t.tz_dsttime = 0x09ABCDEF;
  
  assert((out = malloc(size)) != NULL);
  ret = aconv_struct_timezone(&t, from, to, out);
  assert(ret != ACONV_ERROR);
  if(from == to)
    memcpy(out, &t, size);
  assert(write(fd, out, size) == size);
  free(out);
}
static void test_struct_timezone_r(int fd, enum arch from, enum arch to) {
  struct timezone t;
  int size = aconv_struct_timezone_size(from, to);
  struct timezone *in;
  assert(size == sizeof(struct timezone));
  t.tz_minuteswest  = 0x12345678;
  t.tz_dsttime = 0x09ABCDEF;

  assert((in = malloc(size)) != NULL);
  assert(read(fd, in, size) == size);
  assert(t.tz_minuteswest == in->tz_minuteswest);
  assert(t.tz_dsttime == in->tz_dsttime);
  free(in);
}

static void test_struct_utimbuf_w(int fd, enum arch from, enum arch to) {
  struct utimbuf t;
  int size = aconv_struct_utimbuf_size(from, to);
  int ret;
  void *out;
  t.actime = 0x12345678;
  t.modtime = 0x09ABCDEF;
  
  assert((out = malloc(size)) != NULL);
  ret = aconv_struct_utimbuf(&t, from, to, out);
  assert(ret != ACONV_ERROR);
  if(from == to)
    memcpy(out, &t, size);
  assert(write(fd, out, size) == size);
  free(out);
}

static void test_struct_utimbuf_r(int fd, enum arch from, enum arch to) {
  struct utimbuf t;
  int size = aconv_struct_utimbuf_size(from, to);
  struct utimbuf *in;
  assert(size == sizeof(struct utimbuf));
  t.actime  = 0x12345678;
  t.modtime = 0x09ABCDEF;

  assert((in = malloc(size)) != NULL);
  assert(read(fd, in, size) == size);
  assert(t.actime == in->actime);
  assert(t.modtime == in->modtime);
  free(in);
}
static void test_struct_utsname_w(int fd, enum arch from, enum arch to) {
  struct utsname t;
  int size = aconv_struct_utsname_size(from, to);
  int ret;
  void *out;
  memset(t.sysname, 'a', _UTSNAME_SYSNAME_LENGTH);
  memset(t.nodename, 'b', _UTSNAME_NODENAME_LENGTH);
  memset(t.release, 'c', _UTSNAME_RELEASE_LENGTH);
  memset(t.version, 'd', _UTSNAME_VERSION_LENGTH);
  memset(t.machine, 'e', _UTSNAME_MACHINE_LENGTH);
#if _UTSNAME_DOMAIN_LENGTH - 0
# ifdef __USE_GNU
  memset(t.domainname, 'f', _UTSNAME_DOMAIN_LENGTH);
# else
  memset(t.__domainname, 'g', _UTSNAME_DOMAIN_LENGTH);
# endif
#endif
 
  assert((out = malloc(size)) != NULL);
  ret = aconv_struct_utsname(&t, from, to, out);
  assert(ret != ACONV_ERROR);
  if(from == to)
    memcpy(out, &t, size);
  assert(write(fd, out, size) == size);
  free(out);
}

static void test_struct_utsname_r(int fd, enum arch from, enum arch to) {
  struct utsname t;
  int size = aconv_struct_utsname_size(from, to);
  struct utsname *in;
  assert(size == sizeof(struct utsname));
  memset(t.sysname, 'a', _UTSNAME_SYSNAME_LENGTH);
  memset(t.nodename, 'b', _UTSNAME_NODENAME_LENGTH);
  memset(t.release, 'c', _UTSNAME_RELEASE_LENGTH);
  memset(t.version, 'd', _UTSNAME_VERSION_LENGTH);
  memset(t.machine, 'e', _UTSNAME_MACHINE_LENGTH);
#if _UTSNAME_DOMAIN_LENGTH - 0
# ifdef __USE_GNU
  memset(t.domainname, 'f', _UTSNAME_DOMAIN_LENGTH);
# else
  memset(t.__domainname, 'g', _UTSNAME_DOMAIN_LENGTH);
# endif
#endif

  assert((in = malloc(size)) != NULL);
  assert(read(fd, in, size) == size);
  assert(memcmp(t.sysname, in->sysname, _UTSNAME_SYSNAME_LENGTH) == 0);
  assert(memcmp(t.nodename, in->nodename, _UTSNAME_NODENAME_LENGTH) == 0);
  assert(memcmp(t.release, in->release, _UTSNAME_RELEASE_LENGTH) == 0);
  assert(memcmp(t.version, in->version, _UTSNAME_VERSION_LENGTH) == 0);
  assert(memcmp(t.machine, in->machine, _UTSNAME_MACHINE_LENGTH) == 0);
#if _UTSNAME_DOMAIN_LENGTH - 0
# ifdef __USE_GNU
  assert(memcmp(t.domainname, in->domainname, _UTSNAME_DOMAIN_LENGTH) == 0);
# else
  assert(memcmp(t.__domainname, in->__domainname, _UTSNAME_DOMAIN_LENGTH) == 0);
# endif
#endif

  free(in);
}

static void test_struct_timex_w(int fd, enum arch from, enum arch to) {
  struct timex t;
  int size = aconv_struct_timex_size(from, to);
  int ret;
  void *out;
  t.modes = 0x12345678; /* unsigned int modes */
  t.offset = 0x00abcdefL; /* long offset */
  t.freq = 0x0f112233L; /* long freq */
  t.maxerror = 0x00445566L; /* long maxerror */
  t.esterror = 0x0faabbccL; /* long esterror */
  t.status = 0x0f123456; /* int status */
  t.constant = 0x00778899L; /* long constant */
  t.precision = 0x0fccddeeL; /* long precision */
  t.tolerance = 0x09876543L; /* long tolerance */
  t.time.tv_sec = 0x12345678; /* struct timeval time */
  t.time.tv_usec = 0x09abcdef; /* struct timeval time */
  t.tick = 0x0abcdef6L; /* long tick */
  t.ppsfreq = 0x00778844L; /* long ppsfreq */
  t.jitter = 0x00aaddeeL; /* long jitter */
  t.shift = 0x01112223; /* int shift */
  t.stabil = 0x0f765432L; /* long stabil */
  t.jitcnt = 0x0abcdef2L; /* long jitcnt */
  t.calcnt = 0x01234567L; /* long calcnt */
  t.errcnt = 0x00066551L; /* long errcnt */
  t.stbcnt = 0x021343d7L; /* long stbcnt */

 
  assert((out = malloc(size)) != NULL);
  ret = aconv_struct_timex(&t, from, to, out);
  assert(ret != ACONV_ERROR);
  if(from == to)
    memcpy(out, &t, size);
  assert(write(fd, out, size) == size);
  free(out);
}

static void test_struct_timex_r(int fd, enum arch from, enum arch to) {
  struct timex t;
  int size = aconv_struct_timex_size(from, to);
  struct timex *in;
  assert(size == sizeof(struct timex));
  t.modes = 0x12345678; /* unsigned int modes */
  t.offset = 0x00abcdefL; /* long offset */
  t.freq = 0x0f112233L; /* long freq */
  t.maxerror = 0x00445566L; /* long maxerror */
  t.esterror = 0x0faabbccL; /* long esterror */
  t.status = 0x0f123456; /* int status */
  t.constant = 0x00778899L; /* long constant */
  t.precision = 0x0fccddeeL; /* long precision */
  t.tolerance = 0x09876543L; /* long tolerance */
  t.time.tv_sec = 0x12345678; /* struct timeval time */
  t.time.tv_usec = 0x09abcdef; /* struct timeval time */
  t.tick = 0x0abcdef6L; /* long tick */
  t.ppsfreq = 0x00778844L; /* long ppsfreq */
  t.jitter = 0x00aaddeeL; /* long jitter */
  t.shift = 0x01112223; /* int shift */
  t.stabil = 0x0f765432L; /* long stabil */
  t.jitcnt = 0x0abcdef2L; /* long jitcnt */
  t.calcnt = 0x01234567L; /* long calcnt */
  t.errcnt = 0x00066551L; /* long errcnt */
  t.stbcnt = 0x021343d7L; /* long stbcnt */

  assert((in = malloc(size)) != NULL);
  assert(read(fd, in, size) == size);
  assert(t.modes == in->modes);
  assert(t.offset == in->offset);
  assert(t.freq == in->freq);
  assert(t.maxerror == in->maxerror);
  assert(t.esterror == in->esterror);
  assert(t.status == in->status);
  assert(t.constant == in->constant);
  assert(t.precision == in->precision);
  assert(t.tolerance == in->tolerance);
  assert(t.time.tv_sec == in->time.tv_sec);
  assert(t.time.tv_usec == in->time.tv_usec);
  assert(t.tick == in->tick);
  assert(t.ppsfreq == in->ppsfreq);
  assert(t.jitter == in->jitter);
  assert(t.shift == in->shift);
  assert(t.stabil == in->stabil);
  assert(t.jitcnt == in->jitcnt);
  assert(t.calcnt == in->calcnt);
  assert(t.errcnt == in->errcnt);
  assert(t.stbcnt == in->stbcnt);

  free(in);
}

static void test_struct_statfs64_w(int fd, enum arch from, enum arch to) {
  struct statfs64 s;
  int size = aconv_struct_statfs64_size(from, to);
  int ret;
  void *out;
  s.f_type	  = 0x01234567;
  s.f_bsize	  = 0x09abcdef;
  s.f_blocks	= 0x01122667;
  s.f_bfree	  = 0x0ab45678;
  s.f_bavail	= 0x0afd3455;
  s.f_files	  = 0x06667888;
  s.f_ffree	  = 0x0defffe3;
  s.f_fsid.__val[0] = 0xabbcd232;
  s.f_fsid.__val[1] = 0x12345ade;
  s.f_namelen	= 0x09876543;
  s.f_frsize	= 0x0aacaabb;
  s.f_spare[0]= 0x01112234;
  s.f_spare[1]= 0x02412234;
  s.f_spare[2]= 0x0111ab34;
  s.f_spare[3]= 0x0fd12254;
  s.f_spare[4]= 0x011a22a4;

  assert((out = malloc(size)) != NULL);
  ret = aconv_struct_statfs64(&s, from, to, out);
  assert(ret != ACONV_ERROR);
  if(from == to)
    memcpy(out, &s, size);
  assert(write(fd, out, size) == size);
  free(out);
}

static void test_struct_statfs64_r(int fd, enum arch from, enum arch to) {
  struct statfs64 s;
  int size = aconv_struct_statfs64_size(from, to);
  struct statfs64 *in;
  assert(size == sizeof(struct statfs64));
  s.f_type	  = 0x01234567;
  s.f_bsize	  = 0x09abcdef;
  s.f_blocks	= 0x01122667;
  s.f_bfree	  = 0x0ab45678;
  s.f_bavail	= 0x0afd3455;
  s.f_files	  = 0x06667888;
  s.f_ffree	  = 0x0defffe3;
  s.f_fsid.__val[0] = 0xabbcd232;
  s.f_fsid.__val[1] = 0x12345ade;
  s.f_namelen	= 0x09876543;
  s.f_frsize	= 0x0aacaabb;
  s.f_spare[0]= 0x01112234;
  s.f_spare[1]= 0x02412234;
  s.f_spare[2]= 0x0111ab34;
  s.f_spare[3]= 0x0fd12254;
  s.f_spare[4]= 0x011a22a4;

  assert((in = malloc(size)) != NULL);
  assert(read(fd, in, size) == size);
  assert(s.f_type == in->f_type);	  
  assert(s.f_bsize == in->f_bsize);	  
  assert(s.f_blocks == in->f_blocks);	
  assert(s.f_bfree == in->f_bfree);	  
  assert(s.f_bavail == in->f_bavail);	
  assert(s.f_files == in->f_files);	  
  assert(s.f_ffree == in->f_ffree);	  
  assert(s.f_fsid.__val[0] == in->f_fsid.__val[0]);
  assert(s.f_fsid.__val[1] == in->f_fsid.__val[1]);
  assert(s.f_namelen == in->f_namelen);	
  assert(s.f_frsize == in->f_frsize);	
  assert(s.f_spare[0] == in->f_spare[0]);
  assert(s.f_spare[1] == in->f_spare[1]);
  assert(s.f_spare[2] == in->f_spare[2]);
  assert(s.f_spare[3] == in->f_spare[3]);
  assert(s.f_spare[4] == in->f_spare[4]);

  free(in);
}

static void test_struct_stat64_w(int fd, enum arch from, enum arch to) {
  struct stat64 s;
  int size = aconv_struct_stat64_size(from, to);
  int ret;
  void *out;
  bzero(&s, sizeof(struct stat64));
  s.st_dev = 0x00123456;
#if defined __i386__
  s.__st_ino = 0x00927655;
#else
  s.st_ino = 0x00927655;
#endif
  s.st_mode = 0x001122bb;
  s.st_nlink = 0x00fedab2;
  s.st_uid = 0x00445678;
  s.st_gid = 0x00777666;
  s.st_rdev = 0x001234aa;
  s.st_size = 0x0012cdef;
  s.st_blksize = 0x0099a821;
  s.st_blocks = 0x00123678;
#ifdef __USE_MISC
  s.st_atim.tv_sec  = 0x00abcdab;
  s.st_atim.tv_nsec = 0x00aeedab;
  s.st_mtim.tv_sec  = 0x00ef4546;
  s.st_mtim.tv_nsec = 0x00e22546;
  s.st_ctim.tv_sec  = 0x002be84d;
  s.st_ctim.tv_nsec = 0x0023484d;
#else
  s.st_atime = 0x0044456;
  s.st_atimensec = 0x0054321f;
  s.st_mtime = 0x00fedd34;
  s.st_mtimensec = 0x00eeabcd;
  s.st_ctime = 0x00344567;
  s.st_ctimensec = 0x007888ed;
#endif
  s.st_ino = 0x00927655;

  assert((out = calloc(1, size)) != NULL);
  ret = aconv_struct_stat64(&s, from, to, out);
  assert(ret != ACONV_ERROR);
  if(from == to)
    memcpy(out, &s, size);
  assert(write(fd, out, size) == size);
  free(out);
}

static void test_struct_stat64_r(int fd, enum arch from, enum arch to) {
  struct stat64 s;
  int size = aconv_struct_stat64_size(from, to);
  struct stat64 *in;
  assert(size == sizeof(struct stat64));
  bzero(&s, sizeof(struct stat64));
  s.st_dev = 0x00123456;
#if defined __i386__
  s.__st_ino = 0x00927655;
#else
  s.st_ino = 0x00927655;
#endif
  s.st_mode = 0x001122bb;
  s.st_nlink = 0x00fedab2;
  s.st_uid = 0x00445678;
  s.st_gid = 0x00777666;
  s.st_rdev = 0x001234aa;
  s.st_size = 0x0012cdef;
  s.st_blksize = 0x0099a821;
  s.st_blocks = 0x00123678;
#ifdef __USE_MISC
  s.st_atim.tv_sec  = 0x00abcdab;
  s.st_atim.tv_nsec = 0x00aeedab;
  s.st_mtim.tv_sec  = 0x00ef4546;
  s.st_mtim.tv_nsec = 0x00e22546;
  s.st_ctim.tv_sec  = 0x002be84d;
  s.st_ctim.tv_nsec = 0x0023484d;
#else
  s.st_atime = 0x0044456;
  s.st_atimensec = 0x0054321f;
  s.st_mtime = 0x00fedd34;
  s.st_mtimensec = 0x00eeabcd;
  s.st_ctime = 0x00344567;
  s.st_ctimensec = 0x007888ed;
#endif
  s.st_ino = 0x00927655;
#if 0
  printf("s.st_dev = %p (%d)\n", &s.st_dev, sizeof(s.st_dev));
#if defined __i386__
  printf("s.__st_ino = %p (%d)\n", &s.__st_ino, sizeof(s.__st_ino));
#else
  printf("s.st_ino = %p (%d)\n", &s.st_ino, sizeof(s.st_ino));
#endif
  printf("s.st_mode = %p (%d)\n", &s.st_mode, sizeof(s.st_mode));
  printf("s.st_nlink = %p (%d)\n", &s.st_nlink, sizeof(s.st_nlink));
  printf("s.st_uid = %p (%d)\n", &s.st_uid, sizeof(s.st_uid));
  printf("s.st_gid = %p (%d)\n", &s.st_gid, sizeof(s.st_gid));
  printf("s.st_rdev = %p (%d)\n", &s.st_rdev, sizeof(s.st_rdev));
#ifdef __powerpc__
  printf("s.__pad2 = %p (%d)\n", &s.__pad2, sizeof(s.__pad2));
#endif
  printf("s.st_size = %p (%d)\n", &s.st_size, sizeof(s.st_size));
  printf("s.st_blksize = %p (%d)\n", &s.st_blksize, sizeof(s.st_blksize));
  printf("s.st_blocks = %p (%d)\n", &s.st_blocks, sizeof(s.st_blocks));
#ifdef __USE_MISC
  printf("s.st_atim.tv_sec  = %p (%d)\n", &s.st_atim.tv_sec , sizeof(s.st_atim.tv_sec ));
  printf("s.st_atim.tv_nsec = %p (%d)\n", &s.st_atim.tv_nsec, sizeof(s.st_atim.tv_nsec));
  printf("s.st_mtim.tv_sec  = %p (%d)\n", &s.st_mtim.tv_sec , sizeof(s.st_mtim.tv_sec ));
  printf("s.st_mtim.tv_nsec = %p (%d)\n", &s.st_mtim.tv_nsec, sizeof(s.st_mtim.tv_nsec));
  printf("s.st_ctim.tv_sec  = %p (%d)\n", &s.st_ctim.tv_sec , sizeof(s.st_ctim.tv_sec ));
  printf("s.st_ctim.tv_nsec = %p (%d)\n", &s.st_ctim.tv_nsec, sizeof(s.st_ctim.tv_nsec));
#else
  printf("s.st_atime = %p (%d)\n", &s.st_atime, sizeof(s.st_atime));
  printf("s.st_atimensec = %p (%d)\n", &s.st_atimensec, sizeof(s.st_atimensec));
  printf("s.st_mtime = %p (%d)\n", &s.st_mtime, sizeof(s.st_mtime));
  printf("s.st_mtimensec = %p (%d)\n", &s.st_mtimensec, sizeof(s.st_mtimensec));
  printf("s.st_ctime = %p (%d)\n", &s.st_ctime, sizeof(s.st_ctime));
  printf("s.st_ctimensec = %p (%d)\n", &s.st_ctimensec, sizeof(s.st_ctimensec));
#endif
  printf("s.st_ino = %p (%d)\n", &s.st_ino, sizeof(s.st_ino));
#endif
  /* fprintf(stderr, "Read: expected:\n"); dump(&s, size, to/8); */
  assert((in = malloc(size)) != NULL);
  bzero(in, size);
  assert(read(fd, in, size) == size);
  /* fprintf(stderr, "Read: returned:\n"); dump(in, size, to/8); */
  assert(s.st_dev == in->st_dev);
#if defined __i386__
  assert(s.__st_ino == in->__st_ino);
#else
  assert(s.st_ino == in->st_ino);
#endif
  assert(s.st_mode == in->st_mode);
  assert(s.st_nlink == in->st_nlink);
  assert(s.st_uid == in->st_uid);
  assert(s.st_gid == in->st_gid);
  assert(s.st_rdev == in->st_rdev);
  assert(s.st_size == in->st_size);
  assert(s.st_blksize == in->st_blksize);
  assert(s.st_blocks == in->st_blocks);
#ifdef __USE_MISC
  assert(s.st_atim.tv_sec == in->st_atim.tv_sec);
  assert(s.st_atim.tv_nsec == in->st_atim.tv_nsec);
  assert(s.st_mtim.tv_sec == in->st_mtim.tv_sec);
  assert(s.st_mtim.tv_nsec == in->st_mtim.tv_nsec);
  assert(s.st_ctim.tv_sec == in->st_ctim.tv_sec);
  assert(s.st_ctim.tv_nsec == in->st_ctim.tv_nsec);
#else
  assert(s.st_atime == in->st_atime);
  assert(s.st_atimensec == in->st_atimensec);
  assert(s.st_mtime == in->st_mtime);
  assert(s.st_mtimensec == in->st_mtimensec);
  assert(s.st_ctime == in->st_ctime);
  assert(s.st_ctimensec == in->st_ctimensec);
#endif
  assert(s.st_ino == in->st_ino);

  free(in);
}

/* If from == to I try to send a struct sockaddr_in (in this way
 * I can test its fields without problems), otherwise I sent an
 * array of char */
static void test_bytes_w(int fd, enum arch from, enum arch to) {
  void *out;
  int size, ret;
  char str[256];
  size = aconv_bytes_size(256, from, to);
  memset(str, 'd', 256);
    
  assert((out = calloc(1, size)) != NULL);
  ret = aconv_bytes(str, from, to, out, size);
  assert(ret != ACONV_ERROR);
  if(from == to)
    memcpy(out, str, size);
  assert(write(fd, out, size) == size);
  free(out);
}

static void test_bytes_r(int fd, enum arch from, enum arch to) {
  void *in;
  int size = aconv_bytes_size(256, from, to);
  char str[256];
  assert((in = malloc(size)) != NULL);
  assert(read(fd, in, size) == size);
  memset(str, 'd', 256);
  assert(memcmp(str, in, 256) == 0);


  free(in);
}
/*******************************************************************/
/* Public test functions                                           */
/*******************************************************************/
void test_libaconv_client(int fd, enum arch myarch, enum arch sarch) {
  test_char_w(fd, myarch, sarch);
  test_char_r(fd, sarch, myarch);

  test_u_char_w(fd, myarch, sarch);
  test_u_char_r(fd, sarch, myarch);
  
  test_short_w(fd, myarch, sarch);
  test_short_r(fd, sarch, myarch);
  
  test_u_short_w(fd, myarch, sarch);
  test_u_short_r(fd, sarch, myarch);
  
  test_int_w(fd, myarch, sarch);
  test_int_r(fd, sarch, myarch);
  
  test_u_int_w(fd, myarch, sarch);
  test_u_int_r(fd, sarch, myarch);
  
  test_long_w(fd, myarch, sarch);
  test_long_r(fd, sarch, myarch);
  
  test_u_long_w(fd, myarch, sarch);
  test_u_long_r(fd, sarch, myarch);

  test_longlong_w(fd, myarch, sarch);
  test_longlong_r(fd, sarch, myarch);
  
  test_u_longlong_w(fd, myarch, sarch);
  test_u_longlong_r(fd, sarch, myarch);

  test_string_w(fd, myarch, sarch);
  test_string_r(fd, sarch, myarch);

  test_pointer_w(fd, myarch, sarch);
  test_pointer_r(fd, sarch, myarch);
  
  test_mode_t_w(fd, myarch, sarch);
  test_mode_t_r(fd, sarch, myarch);

  test_loff_t_w(fd, myarch, sarch);
  test_loff_t_r(fd, sarch, myarch);

  test_uid_t_w(fd, myarch, sarch);
  test_uid_t_r(fd, sarch, myarch);

  test_gid_t_w(fd, myarch, sarch);
  test_gid_t_r(fd, sarch, myarch);
  
  test_clockid_t_w(fd, myarch, sarch);
  test_clockid_t_r(fd, sarch, myarch);

  test___off64_t_w(fd, myarch, sarch);
  test___off64_t_r(fd, sarch, myarch);

  test_socklen_t_w(fd, myarch, sarch);
  test_socklen_t_r(fd, sarch, myarch);

  test_socklen_t_w(fd, myarch, sarch);
  test_socklen_t_r(fd, sarch, myarch);

  test_size_t_w(fd, myarch, sarch);
  test_size_t_r(fd, sarch, myarch);

  test_off_t_w(fd, myarch, sarch);
  test_off_t_r(fd, sarch, myarch);

  test_array_w(fd, myarch, sarch);
  test_array_r(fd, sarch, myarch);
  
  test_struct_dirent64_w(fd, myarch, sarch);
  test_struct_dirent64_r(fd, sarch, myarch);
  
  test_struct_sockaddr_w(fd, myarch, sarch);
  test_struct_sockaddr_r(fd, sarch, myarch);
  
  test_struct_timespec_w(fd, myarch, sarch);
  test_struct_timespec_r(fd, sarch, myarch);
  
  test_struct_timeval_w(fd, myarch, sarch);
  test_struct_timeval_r(fd, sarch, myarch);
  
  test_struct_timezone_w(fd, myarch, sarch);
  test_struct_timezone_r(fd, sarch, myarch);
  
  test_struct_utimbuf_w(fd, myarch, sarch);
  test_struct_utimbuf_r(fd, sarch, myarch);
  
  test_struct_utsname_w(fd, myarch, sarch);
  test_struct_utsname_r(fd, sarch, myarch);
  
  test_struct_timex_w(fd, myarch, sarch);
  test_struct_timex_r(fd, sarch, myarch);
  
  test_struct_statfs64_w(fd, myarch, sarch);
  test_struct_statfs64_r(fd, sarch, myarch);
  
  test_struct_stat64_w(fd, myarch, sarch);
  test_struct_stat64_r(fd, sarch, myarch);
  
  test_bytes_w(fd, myarch, sarch);
  test_bytes_r(fd, sarch, myarch);
  
  return NULL;
}

void test_libaconv_server(int fd, enum arch carch, enum arch myarch) {
  
  test_size_fun(carch, myarch);
  test_char_r(fd, carch, myarch);
  test_char_w(fd, myarch, carch);

  test_u_char_r(fd, carch, myarch);
  test_u_char_w(fd, myarch, carch);

  test_short_r(fd, carch, myarch);
  test_short_w(fd, myarch, carch);

  test_u_short_r(fd, carch, myarch);
  test_u_short_w(fd, myarch, carch);

  test_int_r(fd, carch, myarch);
  test_int_w(fd, myarch, carch);
  
  test_u_int_r(fd, carch, myarch);
  test_u_int_w(fd, myarch, carch);
  
  test_long_r(fd, carch, myarch);
  test_long_w(fd, myarch, carch);
    
  test_u_long_r(fd, carch, myarch);
  test_u_long_w(fd, myarch, carch);
  
  test_longlong_r(fd, carch, myarch);
  test_longlong_w(fd, myarch, carch);
    
  test_u_longlong_r(fd, carch, myarch);
  test_u_longlong_w(fd, myarch, carch);

  test_string_r(fd, carch, myarch);
  test_string_w(fd, myarch, carch);
  
  test_pointer_r(fd, carch, myarch);
  test_pointer_w(fd, myarch, carch);
  
  test_mode_t_r(fd, carch, myarch);
  test_mode_t_w(fd, myarch, carch);
  
  test_loff_t_r(fd, carch, myarch);
  test_loff_t_w(fd, myarch, carch);

  test_uid_t_r(fd, carch, myarch);
  test_uid_t_w(fd, myarch, carch);
  
  test_gid_t_r(fd, carch, myarch);
  test_gid_t_w(fd, myarch, carch);

  test_clockid_t_r(fd, carch, myarch);
  test_clockid_t_w(fd, myarch, carch);

  test___off64_t_r(fd, carch, myarch);
  test___off64_t_w(fd, myarch, carch);

  test_socklen_t_r(fd, carch, myarch);
  test_socklen_t_w(fd, myarch, carch);
  
  test_socklen_t_r(fd, carch, myarch);
  test_socklen_t_w(fd, myarch, carch);
  
  test_size_t_r(fd, carch, myarch);
  test_size_t_w(fd, myarch, carch);

  test_off_t_r(fd, carch, myarch);
  test_off_t_w(fd, myarch, carch);

  test_array_r(fd, carch, myarch);
  test_array_w(fd, myarch, carch);
  
  test_struct_dirent64_r(fd, carch, myarch);
  test_struct_dirent64_w(fd, myarch, carch);

  test_struct_sockaddr_r(fd, carch, myarch);
  test_struct_sockaddr_w(fd, myarch, carch);
 
  test_struct_timespec_r(fd, carch, myarch);
  test_struct_timespec_w(fd, myarch, carch);
 
  test_struct_timeval_r(fd, carch, myarch);
  test_struct_timeval_w(fd, myarch, carch);
 
  test_struct_timezone_r(fd, carch, myarch);
  test_struct_timezone_w(fd, myarch, carch);
 
  test_struct_utimbuf_r(fd, carch, myarch);
  test_struct_utimbuf_w(fd, myarch, carch);
 
  test_struct_utsname_r(fd, carch, myarch);
  test_struct_utsname_w(fd, myarch, carch);
 
  test_struct_timex_r(fd, carch, myarch);
  test_struct_timex_w(fd, myarch, carch);
 
  test_struct_statfs64_r(fd, carch, myarch);
  test_struct_statfs64_w(fd, myarch, carch);

  test_struct_stat64_r(fd, carch, myarch);
  test_struct_stat64_w(fd, myarch, carch);
 
  test_bytes_r(fd, carch, myarch);
  test_bytes_w(fd, myarch, carch);
 
  return NULL;
}
