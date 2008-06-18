#!/usr/bin/ruby -w
#   
#   This is part of RSC file generator program
#
#   syscall_constant.rb: Syscall module to store and manage
#                        system call informations
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


require 'c.rb'

#--####################################################################
## CONSTANTS
#++####################################################################

NO_VALUE = "NO_VALUE"

#--####################################################################
## CLASSES
#++####################################################################

# This module contains classes used to store and menage system call informations.
# The class Arch represent an computer architecture. The class Constant a system
# call constant with all the related informations necessary to write the templates.
# The ConstantList represents a system call Constant list.
module Syscall
	# The class Arch represent a computer architecture. The allowed architecture
	# are <em>x86</em>, <em>x86_64</em> and <em>ppc</em>.
	class Arch
	  attr_reader :arch
	  
	  @@allowed_archs = {
	    :x86 => :x86, 
	    :x86_64 => :x86_64, 
	    :ppc => :ppc
	  }.freeze
	  
	  # The _arch_ is String or Symbol with the following values: <em>x86</em>, <em>x86_64</em> or <em>ppc</em>.
	  def initialize(arch)
	    @arch = @@allowed_archs[arch.to_sym]
	    if @arch.nil?
	      raise "Wrong architecture(\"#{arch}\"), I cannot create the object"
	    end
	  end
	
	  # Rteurns a sting representation of the architecture
	  def to_s
	    @@allowed_archs[@arch].to_s
	  end
	end
	
	# The class represent a system call and contains all the useful informations
  # needed by the templates.
	class Constant
	  include Comparable
	
	  attr_accessor :nr, :sys, :rsc, :rsc_num, :name, :headers, :args
	  attr_writer :nr_num, :used_by_umview
	  attr :fake
	
		@@nr_sys = {
			"__RSC_socket" => "SYS_SOCKET",
			"__RSC_bind" => "SYS_BIND",
			"__RSC_connect" => "SYS_CONNECT",
			"__RSC_listen" => "SYS_LISTEN",
			"__RSC_accept" => "SYS_ACCEPT",
			"__RSC_getsockname" => "SYS_GETSOCKNAME",
			"__RSC_getpeername" => "SYS_GETPEERNAME",
			"__RSC_socketpair" => "SYS_SOCKETPAIR",
			"__RSC_send" => "SYS_SEND", # <- I've changed this one
			"__RSC_recv" => "SYS_RECV", # <- I've changed this one
			"__RSC_sendto" => "SYS_SENDTO",
			"__RSC_recvfrom" => "SYS_RECVFROM",
			"__RSC_shutdown" => "SYS_SHUTDOWN",
			"__RSC_setsockopt" => "SYS_SETSOCKOPT",
			"__RSC_getsockopt" => "SYS_GETSOCKOPT",
			"__RSC_sendmsg" => "SYS_SENDMSG",
			"__RSC_recvmsg" => "SYS_RECVMSG"
		}
	
	
    # Initialize the Constant object. _nr_ is the \_\_NR\_\* constant that represent the
    # system call, _num_ is the number associated at the constant _nr_ and _fake
    # is true if the system call is not defined in any <tt>unistd.h</tt> header.
	  def initialize(nr, num, fake = false)
	    @nr = nr.strip
	    @name = @nr.sub(/__NR_/, "")
	    # True if is a fake syscall not defined in any unistd.h file
	    @fake = fake
	    @nr_num = @fake ? -1 : num.to_i
	    @rsc = "__RSC_" + @name
	    @sys = @@nr_sys[@rsc]
	    @rsc_num = -1
	    @used_by_umview = false
	  end
	  
    # true if there is at least a read and write pointer in the system call argument list 
	  def has_rw_args?
	    return @args.find {|arg| arg.rw? }
	  end

    # true if there is at least a read pointer in the system call argument list 
	  def has_read_args?
	    return @args.find {|arg| arg.read? }
	  end

    # true if there is at least a write pointer in the system call argument list 
	  def has_write_args?
	    return @args.find {|arg| arg.write? }
	  end

    # Returns an array containing only the read pointers
    def read_args()
	    list = rearrange_rw_args(:read?)
      return list
    end
    
    # Returns an array containing only the read/write pointers
    def rw_args()
	    list = rearrange_rw_args(:rw?)
      return list
    end

    # Returns an array containing only the write pointers
    def write_args()
	    list = rearrange_rw_args(:write?)
      return list
    end
	
	  
    # This method takes in input an #Argument list (_arg_list_) and re-arrange the 
    # write pointer arguments. Each of these argument is put after its _size_-_var_
    # argument (the argument that contains the size of the pointed memory).
    #
    # This method can be useful when is necessary to generate C code that sends
    # the system call arguments over a socket. In this way are sent the size of the pointed
    # memory and then the content of the pointed memory, in this way the receiver of these data
    # can know the length of the buffer sent, before the data of the buffer arrive.
	  def Constant.swap_write_args(arg_list)
	    list = []
	    arg_list.each { |arg|
	      if(arg.is_size_a_var? && arg.size_var.write?)
	        list << arg.size_var
	      end
	      list << arg if !list.include?(arg)
	    }
	    return list
	  end
	
    # Iterate over the read pointer arguments.
	  def each_read_arg(&block)             # :yields: argument
	    list = rearrange_rw_args(:read?)
	    each = list.method(:each)
	    each.call(&block)
	  end

    # Iterate over the write pointer arguments.
	  def each_write_arg(&block)          # :yields: argument
	    list = rearrange_rw_args(:write?)
	    each = list.method(:each)
	    each.call(&block)
	  end
	  
    # Iterate over the write pointer arguments.
	  def each_write_arg_with_index(&block)       # :yields: argument, index
	    list = rearrange_rw_args(:write?)
	    each = list.method(:each_with_index)
	    each.call(&block)
	  end
	  
    # true if Constant is a fake system call, flase otherwise
	  def fake?() 
      @fake  
    end

    # true if Constant has a SYS\_\* constant. It happens in the architectures (like <em>x86</em> and <em>ppc</em>)
    # where the "socket call" are grouped in one system call: \_\_NR\_socketcall.
	  def sys?() 
      @sys.nil? ? false : true  
    end

    # true if the system call that can be managed by a module of UMVIEW.
	  def used_by_umview?() 
      @used_by_umview 
    end
	  
    # returns the integer value of the \_\_NR\_\* constant of raise an exception
    # if #fake? returns true
	  def nr_num
	    if(@fake)
	      raise "Fake system call doesn't have a number"
	    else
	      @nr_num
	    end
	  end
	
    # Returns a String that representation a Constant object.
	  def to_s
	    string  = "+>> NAME = '#{@name}'; NR = '#{@nr}'(#{@nr_num}), SYS = '#{@sys}', RSC = '#{@rsc}'(#{@rsc_num})\n"
	    string += "|-  FAKE? = '#{@fake}', USED_BY_UMVIEW? = '#{@used_by_umview}'"
	    if(@used_by_umview)
	      string += "\n"
	      string += "|-  HEADERS = #{@headers.join(', ')}\n"
	      string += "|-  ARGUMENTS:\n"
	      @args.each {|arg|
	        string += "    |-  #{arg.inspect}\n"
	      }
	    else
	      string += "\n"
	    end
	
	    return string
	  end
	
    # Compares two Constant objects. These objects are compared by their \_\_NR\_* integer value.
	  def <=>(b)
	    @nr_num <=> b.nr_num
	  end
	
	  ########################################################################
	  ## Private Methods
	  ########################################################################
	  private
    def rearrange_rw_args(selector_method)
	    # Selects only writeable arguments and re-arrange them putting writable-size-vars
	    # before their buffers
	    selected_args = @args.select{|arg| arg.send(selector_method) }
	    list = []
	    selected_args.each do |arg|
	      # arg is a var AND his size is contained in another var AND this size var is non in the list?
	      # If yes, add the size var.
	      if(arg.is_size_a_var? && arg.size_var.send(selector_method) && !list.include?(arg.size_var))
	        list << arg.size_var
	      end
	      list << arg if not list.include?(arg)
      end

      return list
	  end

	end

  # The class is a list of system call Constant.
	class ConstantList < Array
	  attr_accessor :nr_all, :arch
	
    # It takes in input an Hash table where:
    # the keys:: are String representing the \_\_RSC\_* constants used by the _um_rsc_ module 
    #            to identify the system calls
    # the values::  are a object containing the list of headers files needed by the system call
    #               and the list of C.Argument
    #
    # It use this hash table to set the Constant used by UMVIEW and their header and C.Argument lists.
	  def set_used_by_umview(hash)
	    hash.each { |umview_rsc, hdrs_args|
	      self.each { |el| 
	        if(el.rsc == umview_rsc)
	          el.used_by_umview = true 
	          el.headers = hdrs_args.headers
	          el.args = hdrs_args.args
	        end
	      }
	    }
	  end
	   
    # Sort the ConstantList using the \_\_RSC\_* constant and sets the _rsc_num_ of each C.Argument
    # to the position in the sorted list.  
	  def sort_rsc!
	    self.sort!{|a, b| a.rsc <=> b.rsc}
	    self.each_index { |i|
	      self[i].rsc_num = i
	    }
	  end
	
    # Returns the maximum C.Argument in the list.
	  def max
	    max = self.first
	    self.each {|el|
	      if((el <=> max) == 1)
	        max = el
	      end
	    }
	    return max
	  end
	
	  # Returns an array with the only Constant used by UMVIEW.
    def umview()
	    return self.select {|el| el.used_by_umview?}
    end

	  # Iterate only on those Constant that are used by UMVIEW.
    #
    #--
	  # The & convert the block given in input to a Proc object
    #++
	  def each_umview(&block) # :yields: syscall_constant
	    list = self.select {|el| el.used_by_umview?}
	    # here the & convert the Proc to a block, because each takes in
	    # input a block and not a Proc
	    list.each(&block)
	  end
	
    # Merge the ConstantList with _other_syslist_.
	  def merge(other_syslist)
	    hash = self.to_hash(:nr)
	    hash_other_syslist = other_syslist.to_hash(:nr)
	
	    hash.merge!(hash_other_syslist)
	    return ConstantList.hash_to_sysconstlist(hash)
	  end
	
		# Return a string containing a C table <em>rsc_to_<architecture name></em>,
    # used by the _um_rsc_ module to convert a architecture independent 
    # \_\_RSC\_* constant to a architecture dependent \_\_NR\* constant.
		def table_rsc_to_arch()
	    string = String.new
	    hash = to_hash(:nr)
		
		  string << "struct nr_and_sys rsc_to_#{@arch}[] = {\n"
		  i = 0
		  @nr_all.each {|el|
		    arch_el = hash[el.nr]
		    string << "\t/* #{i}. #{el.rsc} */ "
		    if(arch_el.nil?)
		      if(!el.sys.nil? && @arch.arch != :x86_64)
		        @num = hash["__NR_socketcall"].nr_num
		        string << "{#{@num}, #{el.sys}}"
		      else
		        # There isn't a corresponding __NR_ for the given __RSC_ constant in this architecture
		        string << "{#{NO_VALUE}, #{NO_VALUE}}"
		      end
		    else
		      #There is a __NR_* constant but not a SYS_ one
		      string << "{#{arch_el.nr_num}, #{NO_VALUE}}"
		    end
		    string << "#{i != (@nr_all.length - 1) ? "," : ""}\n"
		    i += 1
		  }
		  string << "};\n"
		end
	
			
		# Return a string containing a C table <em><architecture name>_to_rsc</em>,
    # used by the _um_rsc_ module to convert a architecture dependent 
    # \_\_NR\_* constant to a architecture independent \_\_RSC\* constant.
		def table_nr_to_rsc
		  string = table_nr_to_everything("enum rsc_constant", "#{@arch}_to_rsc", true){ |el, not_used| 
		    if(not_used)
		      "__RSC_ERROR"
		    else
		      el.rsc
		    end
		  }
	
	    return string
		end
		
		# Return a string containing a C table <em><architecture name>_to_str</em>,
    # used by the _um_rsc_ module to convert a architecture dependent 
    # \_\_NR\_* constant to string.
		def table_nr_to_str
		  string = table_nr_to_everything("char *", "#{@arch}_to_str"){ |el, not_used| 
		    if(not_used)
		      "\"UNDEFINED\""
		    else
		      "\"#{el.nr}\""
		    end
		  }
	
	    return string
		end
	
		# Return a string containing a C table <em><architecture name>_to_str</em>,
    # used by the _um_rsc_ module to convert a architecture independent 
    # \_\_RSC\_* constant to string.
	  def table_rsc_to_str()
	    string = String.new
	    string << "char *rsc_to_str[] = {\n"
	    self.each_index {|i|
	      el = self[i]
	      string << "\t/* #{i}. #{el.rsc} */ \"#{el.rsc}\"#{i != self.length ? "," : ""}\n"
	    }
	    string << "};\n"
	
	    return string
	  end
	
    # Converts the ConstantList to and Hash table, where each entry has:
    # key::   the key is computed calling the method _key_ of the Constant 
    # value:: the Constant it-self
	  def to_hash(key)
	    hash = Hash.new
	
	    self.each { |el|
	      hash[el.send(key)] = el
	    }
	
	    return hash
	  end
	  
	  #--#####################################################################
	  ## Class Methods
	  #++#####################################################################
    
    # This method is specular to #to_hash, it create a ConstantList from and
    # Hash table.
 	  def self.hash_to_sysconstlist(hash)
	    syscall_list = ConstantList.new
	    hash.each_value { |el|
	      syscall_list << el 
	    }
	    return syscall_list
	  end
	
	  ########################################################################
	  ## Private Methods
	  ########################################################################
	  private
	  # Generic function used to produce the code for "nr_to_rsc" and
		# "nr_to_src" tables.
		def table_nr_to_everything(array_type, array_name, define_size_constant = false)
	    string = String.new
	    hash = to_hash(:nr)
		  
		  max = self.max
		  if(define_size_constant)
		    string << "#define  #{array_name.upcase}_SIZE\t((sizeof(#{array_name}))/(sizeof(#{array_type})))\n"
		  end
		  string << "#{array_type} #{array_name}[] = {\n"
		  (max.nr_num + 1).times {|i|
		    ith_el = self.select{|el| el.nr_num == i unless el.fake? }.first
		    if(ith_el.nil?)
		      string << "\t/* #{i}. NOT USED */ #{yield(ith_el, true)}"
		    else
		      string << "\t/* #{i}. #{ith_el.nr} */ #{yield(ith_el, false)}"
		    end
		    string << "#{i != max.nr_num ? "," : ""}\n"
		  }
		  string << "};\n"
	    
	    return string
		end
	
	end
	

end # module
