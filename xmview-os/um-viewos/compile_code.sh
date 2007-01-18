#!/bin/bash

#   This is part of um-ViewOS
#   The user-mode implementation of OSVIEW -- A Process with a View
#
#   compile_code.sh: generate compiled code for syscalls
#  
#   Copyright 2005 Mattia Belletti
#  
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License, version 2, as
#   published by he Free Software Foundation.
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

# defs.h should define an ASM_SYSCALL constant, which contains the gcc asm code
# which makes a syscall with full arguments (6), read from %0, %1, and so on.
# This script takes the ASM_SYSCALL and gets out the assembly version, with
# indications about where arguments are saved in the code, so that they can be
# filled when needed.
#
# Result will be something like that:
#
# unsigned char asm_syscall[] = { /* the code as hex */ };
# int asm_syscall_args[7] = { /* index in asm_syscall where to save the various
# arguments */ };
#
# That is, the syscall number have to be written in
# asm_syscall[asm_syscall_args[0]], the first argument in
# asm_syscall[asm_syscall_args[1]], and so on.
#
# Output H file goes to $1, C file goes to $2.

OUTFILE_H="$1"
OUTFILE="$2"
DEFS=defs.h
# 6, but there's syscall number too
NUMARGS=7



# Borders are needed as fill-up to put at the borders of our asm code to
# recognize it at the end of processing
STARTBORDER="ZZZZZZZZZZ"
ENDBORDER="ZZZZZZZZZZ"

# First little program: extracts the asm syscall from defs.h and save it into
# $ASM_SYSCALL (escaped and 'stringed' version in $ASM_SYSCALL_CODE)
GET_OUT_ASM=/tmp/getoutasm$$.c
GET_OUT_ASM_ELF=/tmp/getoutasm$$
cat > $GET_OUT_ASM <<_END_
#include <stdio.h>
#include "$DEFS"
int main()
{
	puts(ASM_SYSCALL);
	return 0;
}
_END_
cc -I. -DPIVOTING_ENABLED -Wall -o $GET_OUT_ASM_ELF $GET_OUT_ASM || exit 1
ASM_SYSCALL=`$GET_OUT_ASM_ELF`
ASM_SYSCALL_CODE=`$GET_OUT_ASM_ELF | while read LINE ; do echo "\"$LINE\\n\"" ; done`


# Second little program: makes the set of seven small functions: the first one
# only with zeroes as syscall parameters, and the other 6 with a parameter 1,
# each one for a different argument
FUNCTIONS=/tmp/functions$$.c
FUNCTIONS_ELF=/tmp/functions$$.o
for i in `seq 0 $NUMARGS` ; do
  # head of function
  cat >> $FUNCTIONS <<_END_
void func$i()
{
	asm (
	".ascii \"$STARTBORDER\"\n"
	$ASM_SYSCALL_CODE
	".ascii \"$ENDBORDER\"\n"
	:
	:
_END_
  # insert arguments
  for arg in `seq $NUMARGS` ; do
    if [ $i -eq $arg ] ; then
      echo -n "	\"i\" (-1)" >> $FUNCTIONS
    else
      echo -n "	\"i\" (0)" >> $FUNCTIONS
    fi
    # comma skipped at last argument
    if [ $arg -eq $NUMARGS ] ; then
      echo >> $FUNCTIONS
    else
      echo ", " >> $FUNCTIONS
    fi
  done
  # end of function
  cat >> $FUNCTIONS <<_END_
	);
}
_END_
done



# Third part: extract exadecimal from the compiled functions through objdump
# and some filters.
cc -Wall -pedantic -c -o $FUNCTIONS_ELF $FUNCTIONS || exit 1

PROG='
BEGIN		{ doprint=0; }
/.*func0.*/	{ doprint=1; firstline=1; }
/^[ \t]*$/	{ doprint=0; }
		{ if(doprint) if(!firstline) print $0; else firstline=0; }'
declare -a FUNC
for i in `seq 0 $NUMARGS` ; do
  TRUEPROG=`echo "$PROG" | sed s/func0/func$i/g`
  FUNC[$i]=`objdump -d $FUNCTIONS_ELF | awk "$TRUEPROG" | sed -r 's/^[ \t[:xdigit:]]{,4}:[ \t]*(([[:xdigit:]][[:xdigit:]] ){,8}).*/\1/g' | while read line ; do echo -n "$line " ; done`
done

# Removes 'borders'
function tohex()
{
	three_len=$((`echo -n $1 | wc -c`*3))
	echo -n $1 | hexdump -v | sed -r -e 's/^[[:xdigit:]]*[ \t]*//g' -e 's/ //g' -e 's/([[:xdigit:]][[:xdigit:]])/\1 /g' | while read line ; do echo -n "$line" ; done | cut -c 1-$three_len
}
HEXSTARTBORDER=`tohex $STARTBORDER`
HEXENDBORDER=`tohex $ENDBORDER`
for i in `seq 0 $NUMARGS` ; do
  FUNC[$i]=`echo ${FUNC[$i]} | sed "s/^.*$HEXSTARTBORDER \\(.*\\) $HEXENDBORDER.*$/\\1/"`
done

LENGTH=$((`echo ${FUNC[0]} | wc -c`/3))



# Fourth and last part: make the file. the asm_syscall array is easier, it's
# enough to dump out the FUNC 0, whereas for the other array some comparisons
# have to be made.

# Easy part
# (suppose that if the outfile is called X.c, its header will be X.h
HEADER=`echo $OUTFILE | sed 's/\.c$/.h/'`
cat > $OUTFILE <<_END_
#include "$HEADER"

unsigned char asm_syscall[$LENGTH] = {
_END_
echo ${FUNC[0]} | sed -e 's/^/0x/' -e 's/ /, 0x/g' >> $OUTFILE
cat >> $OUTFILE <<_END_
};
_END_

# Confrontation part
cat >> $OUTFILE <<_END_

int asm_syscall_args[7] = {
_END_
for func in `seq 1 $NUMARGS` ; do
	# confront function "func" with original going through all bytes
	s1=xxx
	s2=xxx
	i=0
	while test $s1 && test $s2 ; do
		s1=`echo ${FUNC[0]} | cut -c $i-$(($i+3))`
		s2=`echo ${FUNC[$func]} | cut -c $i-$(($i+3))`
		if test $s1 != $s2 ; then
			break
		fi
		i=$(($i+3))
	done
	# if we reach here, it means i = three times the place we're looking to
	echo "$(($i/3))," >> $OUTFILE
done
cat >> $OUTFILE <<_END_
};
_END_

# Write out header file
cat > $OUTFILE_H <<_END_
#ifndef SYSCALL_CODE_H_
#define SYSCALL_CODE_H_

#define	ASM_SYSCALL_LENGTH	$LENGTH
unsigned char asm_syscall[ASM_SYSCALL_LENGTH];
int asm_syscall_args[7];

#endif
_END_

rm -f $GET_OUT_ASM $GET_OUT_ASM_ELF $FUNCTIONS $FUNCTIONS_ELF
