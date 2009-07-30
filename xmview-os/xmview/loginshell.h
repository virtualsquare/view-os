#ifndef _LOGINSHELL
#define _LOGINSHELL
#include <string.h>

#define LOGIN_SHELL_ARG0 "viewos-login"
void loginshell_view(void);

static inline int isloginshell(const char *argv0)
{
	int len=strlen(argv0);
	/* argv0 has a -login suffix */
	return(len>6 && strcmp(argv0+(len-6),LOGIN_SHELL_ARG0+6) == 0);
}

#endif
