#ifdef __i386__
#include "kmview_arch_i386.h"
#endif
#ifdef __powerpc__
#ifdef __powerpc64__
#include "kmview_arch_ppc64.h"
#else
#include "kmview_arch_ppc32.h"
#endif
#endif
#ifdef __x86_64__
#include "kmview_arch_x86_64.h"
#endif
