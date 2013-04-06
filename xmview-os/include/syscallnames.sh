#!/bin/bash -e
#set -x

#   This is part of um-ViewOS
#   The user-mode implementation of OSVIEW -- A Process with a View
#
#   syscallnames.sh: extracts correspondence syscall number - syscall name
#  
#   Copyright 2005 Ludovico Gardenghi
#  
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License, version 2, as
#   published by the Free Software Foundation.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License along
#   with this program; if not, write to the Free Software Foundation, Inc.,
#   51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA.
#
#   $Id$
#
#set -x
tmpfile=`mktemp /tmp/scnXXXXXX`
tmpoutfile=`mktemp /tmp/scnXXXXXX`
tmpsfile=`mktemp /tmp/scnXXXXXX`
tmpsoutfile=`mktemp /tmp/scnXXXXXX`

# First step: obtain the total number of system calls
### cat > $tmpfile << _END_
### #include <stdio.h>
### #include <asm/unistd.h>
### 
### int main(void)
### {
### 	printf("%d\n", NR_syscalls);
### 	return 0;
### }
### _END_
### 
### gcc -xc -o "$tmpoutfile" "$tmpfile"
### syscalls=$($tmpoutfile)
### 

# Second step: read system calls names

cat > $tmpfile << _END_
#include <stdio.h>
#include <asm/unistd.h>

int main(void)
{
_END_

echo "#include <asm/unistd.h>" |
  cpp -dN | egrep "^#[[:blank:]]*define[[:blank:]]+__NR_[a-z_]" | 
	tr -s " 	" " " | cut -d" " -f2 | sed 's/__NR_//g' | sort | uniq | while read
do
	cat >> $tmpfile << _END_
#ifdef __NR_$REPLY
	printf("%d\t%s\n", __NR_$REPLY, "$REPLY");
#endif
_END_
done

cat >> $tmpfile << _END_
	return 0;
}
_END_

cat > $tmpsfile << _END_
#include <stdio.h>
#include <linux/net.h>

int main(void)
{
_END_

echo "#include <linux/net.h>" |
	cpp -dN | egrep "^#[[:blank:]]*define[[:blank:]]+SYS_" |
  tr -s "   " " " | cut -d" " -f2 | sed 's/SYS_//g' | sort | uniq | while read
do
	cat >> $tmpsfile << _END_
#ifdef SYS_$REPLY
		printf("%d\t%s\n", SYS_$REPLY, "$REPLY");
#endif
_END_
done

cat >> $tmpsfile << _END_
	return 0;
}
_END_

gcc -xc -o "$tmpoutfile" "$tmpfile"
gcc -xc -o "$tmpsoutfile" "$tmpsfile"

lastscno=-1
cat > syscallnames.h << _END_
#ifndef _SYSCALLNAMES_H
#define _SYSCALLNAMES_H
#include <asm/unistd.h>

static const char *syscallnames[] = {
_END_

$tmpoutfile | sort -n | uniq | ( while read scno scname
do
	if [[ $scno == $lastscno ]]
	then
		# Two system calls with the same number
		continue
	fi
	
	if [[ $scno -gt $(($lastscno + 1)) ]] 
	then
		for i in `seq $(($lastscno+1)) $(($scno-1))`
		do
			echo "	/* $i */ \"UNKNOWN($i)\","
		done
	fi
	echo "	/* $scno */ \"$scname\","
	lastscno=$scno
done >> syscallnames.h

scsize=$(($lastscno + 1))

cat >> syscallnames.h << _END_
};

static const int syscallnames_size = $scsize;

#define SYSCALLNAME(n) (((n) < syscallnames_size) ? syscallnames[(n)] : "OUTOFBOUNDS")

#ifdef __NR_socketcall
static const char *sockcallnames[] = {
_END_

lastscno=-1
$tmpsoutfile | sort -n | uniq | ( while read scno scname
do
		if [[ $scno == $lastscno ]]
	then
# Two system calls with the same number
	continue
	fi

	if [[ $scno -gt $(($lastscno + 1)) ]] 
	then
	for i in `seq $(($lastscno+1)) $(($scno-1))`
	do
		echo "  /* $i */ \"UNKNOWN($i)\","
		done
	fi
	echo "  /* $scno */ \"$scname\","
	lastscno=$scno
done >> syscallnames.h

socksize=$(($lastscno + 1))

cat >> syscallnames.h << _END_
};
static const int sockcallnames_size = $socksize;

#define SOCKCALLNAME(n) (((n) < sockcallnames_size) ? sockcallnames[(n)] : "OUTOFBOUNDS")
#endif
#endif
_END_

cat > nrsyscalls.h << _END_
#ifndef _NRSYSCALLS_H
#define _NRSYSCALLS_H
#include <asm/unistd.h>

#define _UM_NR_syscalls $scsize
#ifdef __NR_socketcall
#define _UM_NR_sockcalls $socksize
#endif

#endif
_END_
)
)

rm -f "$tmpfile" "$tmpoutfile" "$tmpsfile" "$tmpsoutfile"
