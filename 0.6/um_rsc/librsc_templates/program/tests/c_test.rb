#!/usr/bin/ruby
#   
#   This is part of RSC file generator program
#
#   c_test.rb: UnitTest for C module
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


require File.join(File.dirname(__FILE__), '..', 'src', 'c.rb')
require 'test/unit'

module C
	# This class is a Unit::Test for the C.Type class.
	class TypeTest < Test::Unit::TestCase
	  def test_object
	    # Testing object variables
	    t1 = C::Type.new(" \t\t  struct   \t   foo  \t\t  *  \t    ", false)
	    t2 = C::Type.new("const int", true)
	    assert_equal false, t1.const?
	    assert_equal true, t2.const?
	
	    assert_equal true, t1.struct?
	    assert_equal false, t2.struct?
	    
	    assert_equal true, t1.pointer?
	    assert_equal false, t2.pointer?
	
	    assert_equal "struct foo *", t1.type
	    assert_equal "const int", t2.type
	    
	    assert_equal false, t1.array?
	    assert_equal false, t2.array?
	    
	    assert_equal 0, t1.array_size
	    assert_equal 0, t2.array_size
	
	    t3 = C::Type.new("const int", true, :array => true, :array_size => 10)
	    assert_equal true, t3.array?
	    assert_equal 10, t3.array_size
	
	    
	  end
	
	  def test_printf_conv_spec
	    # Testing printf character 
	    
	    types = [ [["int *", 'struct timeval'], '%p'],
	              [["int", "size_t", "socklen_t", "mode_t", "uid_t", "gid_t", "off_t"], '%ld'],
	              [["unsigned int"], '%u'],
	              [["unsigned long int", "nfds_t"], '%lu']
	    ]
	
	    types.each { |types, char|
	      types.each { |type|
	        t1 = C::Type.new(type, false)
	        assert_equal char, t1.printf_conv_spec
	      }
	    }
	
	    # A unmanaged type raise an exception
	    t2 = C::Type.new("foo", false)
	    assert_raise(RuntimeError) { t2.printf_conv_spec }
	  end
	end
	
	# This class is a Unit::Test for the C.Argument class.
	class ArgumentTest < Test::Unit::TestCase
	  
	  def test_new
	
	    # Testing exceptions
	    assert_raise(RuntimeError) { C::Argument.new('int *a') }
	    assert_raise(RuntimeError) { C::Argument.new('int a{R}') }
	    assert_raise(RuntimeError) { C::Argument.new('int a{W}') }
	    assert_raise(RuntimeError) { C::Argument.new('int a{RW}') }
	    assert_raise(RuntimeError) { C::Argument.new('int a{bad_value}') }
	
	    # Testing boolean arguments: read?, write? and is_size_a_var?
	    v1 = C::Argument.new('int *a{R}[a]')
	    assert_equal true, v1.read?
	    assert_equal false, v1.write?
	    
	    v2 = C::Argument.new('int *a{W}')
	    assert_equal false, v2.read?
	    assert_equal true, v2.write?
	    
	    v3 = C::Argument.new('int *a{RW}')
	    assert_equal true, v3.read?
	    assert_equal true, v3.write?
	
	    assert_equal true, v1.is_size_a_var?
	    assert_equal false, v2.is_size_a_var?
	    
	    v4 = C::Argument.new('int a')
	    assert_equal false, v4.read?
	    assert_equal false, v4.write?
	    assert_equal false, v4.is_size_a_var?
	
	    # Testing right type menagement
	    assert_equal 'unsigned long int', C::Argument.new('unsigned long int a').type.type
	    assert_equal 'unsigned int', C::Argument.new('unsigned int a').type.type
	    
	  end
	
	  def test_size
	    # size of a non-pointer var
	    v1 = C::Argument.new('int a')
	    assert_equal nil, v1.size
	
	    # size if a non-pointer var
	    v3 = C::Argument.new('const int *a{R}[size]')
	    v3.size_var = C::Argument.new('int size')
	    assert_equal "size", v3.size
	    assert_equal "struct->size", v3.size("struct->")
	
	    # size if a pointer var
	    v3 = C::Argument.new('const int *a{R}[size]')
	    v3.size_var = C::Argument.new('int *size{R}')
	    assert_equal "*size", v3.size
	    assert_equal "*(struct->size)", v3.size("struct->")
	
	    # size isn't a var
	    v2 = C::Argument.new('const int *a{R}')
	    assert_equal "sizeof(int)", v2.size
	
	    # the variable is a string
	    v4 = C::Argument.new('char *a{R}')
	    assert_equal "(strlen(a) + 1)", v4.size
	
	  end
	
	  def test_size_retval
	
	    v3 = C::Argument.new('const int *a{R}[size]<retval>')
	    assert_equal true, v3.size_retval?
	    
	    v3 = C::Argument.new('const int *a{R}[size]')
	    assert_equal false, v3.size_retval?
	  end
	end
end
