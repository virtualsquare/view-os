#!/bin/bash -e

tmpfile=`mktemp /tmp/scnXXXXXX`
tmpoutfile=`mktemp /tmp/scnXXXXXX`

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


egrep "^#[[:blank:]]*define[[:blank:]]+__NR_" /usr/include/asm/unistd.h | 
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

gcc -xc -o "$tmpoutfile" "$tmpfile"

lastscno=-1


cat > syscallnames.h << _END_
#ifndef _SYSCALLNAMES_H
#define _SYSCALLNAMES_H

const char *syscallnames[] = {
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

const int syscallnames_size = $scsize;

#define SYSCALLNAME(n) (((n) < syscallnames_size) ? syscallnames[(n)] : "OUTOFBOUNDS")

#endif
_END_
)
rm -f "$tmpfile" "$tmpoutputfile"
