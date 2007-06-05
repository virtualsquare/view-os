#   
#   This is part of RSC file generator program
#
#   common_code.rb: common ruby code used by different templates
#   
#   Copyright (C) 2007 Andrea Forni
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

# Returns the string to us in aconv functions:
# aconv_<returned string>() and aconv_<returned string>_size()
# If pointed == true and the type of "arg" is apointer, 
# the functions returns the name or the function
# that manage the pointed memory, not the pointer it-self.
def arg2aconv(arg, pointed = false)
  raise ArgumentError.new("arg must be a C::Argument, not #{type.class}") if arg.class != C::Argument
  type = arg.type.type.clone
  if(pointed)
    type.sub!(/\*/, '');
    type.strip!
  end
  if(arg.type.pointer? and not pointed)
    return "pointer"
  elsif(arg.type.array? and not pointed)
    return "array"
  elsif(arg.type.type =~ /char \*/ or (arg.type.type =~ /void \*/ and arg.type.act_as_a_string?))
    return "string"
  elsif(arg.type.type == "void *")
    return "bytes"
  elsif(arg.type.struct?)
    return type.sub(/ /, '_')
  elsif(arg.type.type == "unsigned long int")
    return "u_long"
  elsif(arg.type.type == "unsigned int")
    return "u_int"
  else
    return type
  end
end

# Returns a string aconv_<argument's type>().
# "arg" is the argument, "a1", "a2" the two architectures 
# and "pointer" is the 4th argument of aconv_<type>() function.
def aconv(arg, a1, a2, pointer, pointed = false, prefix = "", arg_postfix = "")
  typename = arg2aconv(arg, pointed)
  str = "aconv_#{arg2aconv(arg, pointed)}("
  if(not arg.type.pointer? or not arg_postfix.empty?)
     str += "&"
  end
  str += "#{prefix}#{arg.name}#{arg_postfix}, #{a1}, #{a2}, #{pointer}"
  if(typename == "bytes")
    if(arg.size_var.type.pointer?)
      str += ", *(#{prefix}#{arg.size_var.name}#{arg_postfix})"
    else
      str += ", #{prefix}#{arg.size_var.name}#{arg_postfix}"
    end
  end
  str += ")"
  
  if(typename == "array") 
    # FIXME se the FIXME on aconv_size
    str = "aconv_#{typename}(#{arg.name}, #{a1}, #{a2}, #{arg.type.array_size}, #{pointer}, aconv_struct_timeval_size, aconv_struct_timeval)"
  end
  return str
end

# Returns a string aconv_<argument's type>_size().
# "arg" is the argument, and "a1", "a2" the two architectures
def aconv_size(arg, a1, a2, pointed = false, prefix = "")
  # If the argument is a write char pointer, I don't use the 
  # aconv_*_size() function, but the arg_size
  if(pointed and arg.type.type =~ /char \*/ and arg.is_size_a_var?)
    return "#{prefix}#{arg.size_var.name}"
  end

  typename = arg2aconv(arg, pointed)
  func_name = "aconv_#{typename}_size"
  str = "#{func_name}(#{a1}, #{a2})"
  if(typename == "string")
    str = "#{func_name}(#{prefix}#{arg.name}, #{a1}, #{a2})"
  elsif(typename == "array")
    # FIXME: in this way it works because I know that the only array argument is in utimes,
    # I need to change it for the future.
    str = "#{func_name}(#{a1}, #{a2}, #{arg.type.array_size}, aconv_struct_timeval_size)"
  elsif(typename == "bytes")
    if(arg.size_var.type.pointer?)
      str = "#{func_name}(*(#{prefix}#{arg.size_var.name}), #{a1}, #{a2})"
    else
      str = "#{func_name}(#{prefix}#{arg.size_var.name}, #{a1}, #{a2})"
    end
  end
  return str
end

# Patch for 
@@special_syscall = {
  "__RSC_chown32" => ["__powerpc__", "__x86_64__"],
  "__RSC_lchown32" => ["__powerpc__", "__x86_64__"],
  "__RSC_fchown32" => ["__powerpc__", "__x86_64__"],
  "__RSC__llseek" => ["__x86_64__"],
  "__RSC_recv" => ["__x86_64__"],
  "__RSC_send" => ["__x86_64__"]
}

@@x86_64_without64 = [
	'__NR_fstat64',
	'__NR_fstatfs64',
	'__NR_ftruncate64',
	'__NR_lchown32',
	'__NR_lstat64',
	'__NR_recv',
	'__NR_send',
	'__NR_stat64',
	'__NR_statfs64',
	'__NR_truncate64'
]
