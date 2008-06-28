#   
#   This is part of RSC file generator program
#
#   test_common_code.rb: common ruby code used by different templates
#                        implementing librsc test files
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

def compare_func_name(arg)
  fun_name = "compare_"
  if(arg.type.type =~ /void/)
    fun_name += "mem"
  elsif(arg.type.type =~ /char */)
    fun_name += "string"
  else
    fun_name += arg.type.type.sub("\*", "").strip.gsub(" ", "_")
  end

  return fun_name
end

