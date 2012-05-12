#!/usr/bin/ruby -w
#   
#   This is part of RSC file generator program
#
#   c.rb: module representing C types
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


# This module implements the classes Type and Argument used by the main
# script. The class Type represent a C type, the Argument class an argument
# of the system call.
module C
  # It takes in input an argument list (_args_list_) and 
  # adjust the _size_var_ attribute of each argument with Type _pointer_.
  # In fact this attribute is initially set to a string with the name of
  # the attribute containing the size of the pointed memory.
  def self.adjust_size_var_ref(args_list)
    args_list.each { |arg|
      if not arg.size_var.nil?
        arg.size_var = args_list.find{ |arg2| arg.size_var == arg2.name }
        if(not arg.size_var.nil?)
          arg.size_var.is_a_size_var = true
          arg.size_var.pointer_arg = arg
        end
      end
    }
  end

  # The class Type try to represent all the C type of the system call's argument used by
  # UMVIEW. 
  class Type
	  attr_reader :type, :array_size
	
    # The initialization function takes 2 mandatory arguments:
    # * _type_: is the type represented by the object
    # * _const_: true if is a constant type, false otherwise
    # And some options. The allowed options are:
    # * <tt>:array</tt> : true if the type is an <tt>array of <em>type</em></tt>, false otherwise
    # * <tt>:array_size</tt> : is equal to the size of the array if +array+ = true, 0 otherwise
    #
	  def initialize(type, const, options = {})
	    @type = type.strip.gsub(/\s+/, ' ')
      @const = const
	    @struct  = (@type =~ /^struct/) ? true : false
	    @pointer = (@type =~ /\*$/)     ? true : false
      @array = false
      @array_size = 0
      @act_as_a_string = false

      if(options[:array])
        @array = true
        if(options[:array_size])
          @array_size = options[:array_size]
        end
      elsif(options[:act_as_a_string])
        @act_as_a_string = options[:act_as_a_string]
      end
	  end

    # True if the type is constant, false otherwise.
	  def const?() 
      @const 
    end

    # True if the type is a structure, false otherwise.
	  def struct?() 
      @struct 
    end

    # True if the type is an array, false otherwise.
	  def array?() 
      @array 
    end
	  
    # True if the type is a pointer, false otherwise.
    def pointer?() 
      @pointer 
    end
    
    # True if the type is a pointer with a type different from <tt>char *</tt> 
    # but it behaves as it is
    def act_as_a_string?() 
      @act_as_a_string
    end

    # Return a string with the appropriate <em>conversion specification</em> to use with +printf+
    # function. For example for the type :
    # +int+:: the sting returned is "<tt>%ld</tt>"
    # <tt>unsinged int</tt>:: the string returned id "<tt>%u</tt>"
    # and so on
    def printf_conv_spec()
      int = ["int", "size_t", "socklen_t", "mode_t", "uid_t", "gid_t", "off_t", "off64_t", "__off64_t", "clockid_t"]
      unsigned_long_int = ["unsigned long int", "nfds_t"]
      char = ""
      # "It's a "char *", but not an array of "char *"
      #if (@type == 'char *') && (not self.array?)
      #  char = "%s"
      #els
      if @pointer || @type == 'struct timeval'
        char = "%p"
      elsif int.include? @type
        char = "%ld"
      elsif @type == "unsigned int"
        char = "%u"
      elsif unsigned_long_int.include? @type
        char = "%lu"
      else
        raise "printf_conv_spec doesn't menage type '#{@type}'"
      end

      return char
    end

    def to_s 
      string = ""
      #string += "const " if @const
      string += "#{@type.to_s}"
    end

    def inspect
      "'#{@type}'. c? = #{@const}; s? = #{@struct}; p? = #{@pointer}; a? = #{@array}; as = #{@array_size}"
	  end


	end
	
  # The class represent a system call argument. 
	class Argument
	  attr_accessor :type, :name, :size_var, :pointer_arg
    attr_writer :is_a_size_var
    attr_reader :read, :write, :size_retval
    

    # The initialize function is an overloaded functions that can take to sets of different arguments. 
    # ----
    # The first set is composed by one argument: 
    # _string_:: a C variable declaration string to parse to extract all the informations
    #
    # ----
    # The second set is composed by six arguments:
    # _type_:: is a Type object with the type variable
    # _name_:: is the name of the variable
    # The other arguments are valid only if the _type_ is a _pointer_:
    # _read_:: is true if the memory pointed is only read by the system call and not modified, false otherwise
    # _write_:: is true if the memory pointed is modified by the system call, false otherwise
    # _size_var_:: is set to the name of another system call argument that contains the size of the pointed memory
    # _size_retval_:: is true if the return value of the system call gives the exact size of the
    #                 pointed memory used
    # A _value_-_result_ variable has both _read_ and _write_ set to true.
    #
	  def initialize(*args)
      case args.size
        when 1
	        @type, @name, @read, @write, @size_var, @size_retval  = parse_string(args.first)
        when 6
	        @type , @name, @read, @write, @size_var, @size_retval = args
	        @type.strip!
	        @name.strip!
        else
          raise ArgumentError, "This method takes either 1 or 6 arguments."
	    end
      @size = nil

      if(@type.pointer? && !@read && !@write)
	      raise "The type '#{@type}' is a pointer and it needs the R|W|RW flag"
      elsif((@read || @write) && !@type.pointer?)
	      raise "The type '#{@type}' has the R|W|RW flag but it's not a pointer"
      end

      @is_a_size_var = false
      @pointer_arg = nil

	  end

    # If the Type of the Argument object is a pointer this method returns a string of C code that 
    # calculate the size of the pointed memory; otherwise returns nil.
    #
    # The _pre_string_ optional arguments it's used to prepend a string to the name of the Argument or
    # to the name of the Argument that specify the size of the pointed memory. 
    # 
    # Example: you have the Argument is <tt>char *foo</tt> and in you C code, this argument is saved in
    # a filed of the structure <tt>struct bar s</tt> with the same name; so you can access +foo+ thought +s+ in this way: <tt>s.foo</tt>
    # Now, if you call #size without the _pre_string_ you get <tt>(strlen(foo) + 1)</tt>, but this piece of
    # code is wrong because +foo+ is inside a structure. To resolve the problem, you pass the string 's.'
    # to #size and you get <tt>(strlen(s.foo) + 1)</tt>.
    def size(pre_string = "")
      if !@type.pointer?
	      @size = nil
	    elsif is_size_a_var?
	      @size = "#{pre_string}#{@size_var.name}"
	      if @size_var.type.pointer?
	        if pre_string.empty?
	          @size = "*#{@size}"
	        else
	          @size = "*(#{@size})"
	        end
	      end
      elsif (@type.type == "char *" or @type.act_as_a_string?) # Is a string (A char pointer) without a length var
        @size = "(strlen(#{pre_string}#{@name}) + 1)"
	    else
	      @size = "sizeof(#{@type.type[/(?:const *)?((\w+ *)+)(?: *\*)?/, 1].strip})"
	    end

      return @size
    end

    # Returns true if the Argument is a size var for another Argument, in other words it contains
    # the size of the memory pointed by another Argument.
    def is_a_size_var?
      return @is_a_size_var
    end

    def rec_xdr_func(str_type, is_pointer, is_struct, is_array, array_size, xdr, var, size, arch1, arch2)
      needs_4args = ['xdr_long2', 'xdr_u_long2', 'xdr_off_t', 'xdr_nfds_t', 'xdr___time_t', 'xdr___suseconds_t', 'xdr_utimbuf']
      func = ""
      if is_pointer
        if str_type == "char *"
          func = "xdr_string(#{xdr}, &(#{var}), #{size})"
        elsif str_type == "void *"
          func = "xdr_vector(#{xdr}, (char *)(#{var}), #{size}, sizeof(int), (xdrproc_t)xdr_u_int)"
        else
          foo_type = Argument.new(str_type.sub(/\*$/, '') + " foo").type
          f = rec_xdr_func(foo_type.type, foo_type.pointer?, foo_type.struct?, foo_type.array?, foo_type.array_size, xdr, var, size, arch1, arch2).sub(/\(.*\)/, '');
          func = "xdr_pointer(#{xdr}, (char **)&(#{var}), sizeof(#{foo_type.type}), (xdrproc_t)#{f})"
        end
      elsif is_array
        foo_type = Argument.new(str_type + " foo").type
        f = rec_xdr_func(foo_type.type, foo_type.pointer?, foo_type.struct?, foo_type.array?, foo_type.array_size, xdr, var, size, arch1, arch2).sub(/\(.*\)/, '');
        func = "xdr_vector(#{xdr}, (char *)(#{var}), #{array_size}, sizeof(#{str_type}), (xdrproc_t)#{f})"
      elsif is_struct
        func = "xdr_#{str_type.sub(/struct/, '').strip}(#{xdr}, &#{var})"
      else 
        f =  case
                when str_type == 'int': 'xdr_int'
                when str_type == 'unsigned int': 'xdr_u_int'
                when str_type == 'long' || str_type == 'long int': 'xdr_long2'
                when str_type == 'unsigned long' || str_type == 'unsigned long int': 'xdr_u_long2'
                else "xdr_#{str_type}"
             end
        func = "#{f}(#{xdr}, &#{var}"
        func += ", #{arch1}, #{arch2}" if needs_4args.include? f
        func += ")"
      end

      return func
    end

    def xdr_func(xdr, var, size, arch1, arch2)
      rec_xdr_func(@type.type, @type.pointer?, @type.struct?, @type.array?, @type.array_size, xdr, var, size, arch1, arch2)
    end
	
	  def parse_string(string)
	    string.strip!
	    type = nil
	    varname = nil
	    puts "\nparse_string: string to parse = '#{string}'." if $DEBUG

      type = '(const)? *((?:(?:struct +\w+)|(?:(?:(?:unsigned)? *(?:long)? *)(?:\w+))) *(?:\*?))'
      varname = '(\w+)'
      array_size = '(?:\[(\d+)\])?'
      buf_rw = '\{((?:\w*))\}'
      buf_size_var = '(?:\[(:?\w+)\])?'
      buf_retval = '(?:<(retval)>)?'
      buff_act_as = '(?:=(act_as_a_string)=)'
      buf_attr = "(?:#{buf_rw}(?:#{buff_act_as}|(?:#{buf_size_var}#{buf_retval})))?"
      regexp = Regexp.new("#{type} *#{varname}#{array_size}#{buf_attr}")
      res = nil
	    if(res = regexp.match(string))
	      const = res[1].nil? ? false : true
        type_str = res[2]
	      varname = res[3]
        array_size = res[4]
	      rw = res[5]
        act_as_a_string = res[6]
	      size = res[7]
	      retval = res[8].nil? ? false : true
        if($DEBUG) 
          puts "=> Groups in the regexp:"
          puts "\t$1 = #{$1}"
          puts "\t$2 = #{$2}" 
          puts "\t$3 = #{$3}"
          puts "\t$4 = #{$4}"
          puts "\t$5 = #{$5}"
	        puts "\t$6 = #{$6}"
          puts "\t$7 = #{$7}"
          puts "\t$8 = #{$8}"
          puts "\t$9 = #{$9}"
        end
        if(!array_size.nil?)
	        type = Type.new(type_str, const, :array => true, :array_size => array_size.to_i)
        else
	        type = Type.new(type_str, const, :act_as_a_string => (not act_as_a_string.nil?))
        end
        if($DEBUG)
          puts "=> Type object created:"
          puts type.inspect
        end

        read = write = false
        if(!rw.nil?)
          if rw.to_sym == :R
            read = true
          elsif rw.to_sym == :W
            write = true
          elsif rw.to_sym == :RW
            read = write = true
          else
            raise "'#{rw}' is not a right value for the R|W|RW flag"
          end
        end
      end
     
	    return [type, varname, read, write, size, retval]
	  end
	
    def to_s
      string = "#{@type}"
      string += @type.pointer? ? "" : " "
      string += "#{@name}"
      if(@type.array?)
        string += "[#{@type.array_size}]"
      end

      return string
    end
	  
    # returns true if the size of the pointed memory is contained in another Argument.
    def is_size_a_var?() 
      !@size_var.nil? 
    end

    # returns true if the size of the pointed memory is determined by the system call return value.
    def size_retval?() 
      @size_retval 
    end

    # returns true if the pointed memory is read and written by the system call.
    def rw?() 
      @read and @write
    end

    # returns true if the pointed memory is only read by the system call and not modified.
    def read?() 
      @read 
    end
	  
    # returns true if the pointed memory is written by the system call.
    def write?() 
      @write 
    end

	  def inspect
	    "(#{self.object_id})> '#{@name}'; s = '#{@size}'; r? = #{@read}; w? = #{@write}; srv = #{@size_retval}; t = #{@type.inspect}"
	  end
	  
	  private :parse_string, :rec_xdr_func
	end
end

if(__FILE__ == $0)
  SCRIPT_DIR = File.dirname __FILE__
	File.open("#{SCRIPT_DIR}/../input_files/syscalls_rsc.list", "r") { |file|
	  file.each() { |line|
	    line.strip!
	    # I'm not interested in empty lines or comments
	    if(line !~ /^#|^$/)
	      rsc_const, args, headers = line.split("|").collect{|el| el.strip! }
	      str_arg_list = args.split(',')
	      arg_list = []
	      str_arg_list.each { |str_arg|
	        arg_list << C::Argument.new(str_arg)
	      }
	
	      header_list = headers.split(',')
	    end
	  }
	}
end
