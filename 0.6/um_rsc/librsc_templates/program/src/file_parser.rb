#!/usr/bin/ruby -w
#   
#   This is part of RSC file generator program
#
#   file_parser.rb: Parser class used to parse unistd.h header files
#                   and syscall list file
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


require 'optparse'
require 'ostruct'

require 'c.rb'
require 'syscall_constant.rb'

#--####################################################################
## COSTANTS
#++####################################################################

# This class parses different type of file. See the different class methods.
class Parser
	# Parses the unistd.h header _filename_ to extract the \_\_NR_* constants
  # and their integer value.
  #
  # Returns an hash table where the key is the \_\_NR\_* constant and
  # the value is a Syscall.Constant
	def self.parse_unistd(filename)
	  hash = Hash.new
	  File.open(filename, "r") { |f|
	    f.each() { |line|
	      if(line =~ /^#define (__NR_\w*)\s+?(.*)/)
	        nr = $1.strip
	        num = $2.strip
	        #puts "Extracted from Regexp: nr = '#{nr}'; num = '#{num}'"
	        if(num =~ /\((\w+)\+(\d+)\)/)
	          nr_ref = $1
	          n = $2.to_i
	          num = hash[nr_ref].nr_num + n
	        elsif(num =~/__NR_\w+/)
	          num = hash[num].nr_num
	        end
	        hash[nr] = Syscall::Constant.new(nr, num.to_i)
	      end
	    }
	  }
	
	  return Syscall::ConstantList.hash_to_sysconstlist(hash)
	end
	
  # Parse the syslist _filename_ and returns an hast table, where the 
  # key is a \_\_RSC\_* string and the value is a OpenStruct with the
  # following attributes:
  # _args_:: containing the system call argument list 
  # _headers_:: containing the C headers required by the system call
	def self.parse_syslist(filename)
	  hash = {}
		File.open(filename, "r") { |file|
		 file.each() { |line|
		   line.strip!
		   # I'm not interested in empty lines or comments
		   if(line !~ /^#|^$/)
		     rsc_const, args, headers = line.split("|").collect{|el| el.strip! }
		     str_arg_list = args.split(',')
		     arg_list = []
		     str_arg_list.each { |str_arg|
	         begin
	           arg_list << C::Argument.new(str_arg)
		       rescue Exception => e
	           $stderr.puts "Error parsing #{rsc_const} line: #{e}"
	           $stderr.puts e.backtrace
	           exit(-1)
	         end
		     }
		     header_list = headers.split(',').collect{|el| el.strip}
	       C::adjust_size_var_ref(arg_list)
	
	       hash[rsc_const] = OpenStruct.new
	       hash[rsc_const].args = arg_list
	       hash[rsc_const].headers = header_list
		   end
		 }
		}
	
	  return hash
	end

end
