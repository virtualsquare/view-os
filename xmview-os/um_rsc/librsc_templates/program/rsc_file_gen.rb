#!/usr/bin/ruby -w
#   
#   This is part of RSC file generator program
#
#   rsc_file_gen.rb: the RSC file generator program
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
#   You should have received a copy of the GNU General Public License along
#   with this program; if not, write to the Free Software Foundation, Inc.,
#   51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA.
#

$:.unshift File.join(File.dirname(__FILE__), "src")

require 'optparse'
require 'ostruct'
require 'pp'
require 'erb'

require 'c.rb'
require 'syscall_constant.rb'
require 'file_parser.rb'

#######################################################################
## COSTANTS
#######################################################################

REGEXP_TEMPLATE_EXT = /\.(c|h)$/

#######################################################################
## LOCAL FUNCTIONS
#######################################################################
def create_file(complete_path, text)
  prepare_file(complete_path)
  File.open(complete_path, "w") { |f| f.printf("%s", text) }
end

def get_binding(nr_x86, nr_x86_64, nr_ppc, nr_all)
  return binding()
end

# Test if the directories in the path of "filename" exists and, if not, it
# create them. 
# Then tests if the file already exits and backup, in this way a backup copy
# always exists
def prepare_file(filename, backup_file = true)
  dir = File.dirname filename
  # If the directory doesn't exist, create it
  if(!File.exists? dir)
    dirpath = ""
    dir.each("/") {|dir| 
      dir.sub!(/\//, "")
      dirpath += dir + "/" 
      #puts "==> #{dirpath}"
      Dir.mkdir dirpath unless File.exists? dirpath
    }
  end
end

#######################################################################
## MAIN PROGRAM
#######################################################################

# Parsing arguments
opts = OptionParser.new { |opts|
  opts.program_name = __FILE__
  opts.banner = "Usage #{opts.program_name} syscall_list_file unistd_dir/ templates_dir/ librsc_dir/"
  opts.separator ""
  opts.separator "The program needs 4 argument, the first 3 are input arguments:"
  opts.separator "   - 'syscall_list_file' is the file containing the system calls description."
  opts.separator "   - 'unistd_dir' is the directory containing the 4 unistd.h headers, "
  opts.separator "      one for each architecture (unistd_ppc.h, unistd_x86_64.h, unistd_x86.h)."
  opts.separator "   - 'templates_dir' is the directory containing the templates to parse"
  opts.separator "The last argument ('librsc_dir') is the base output directory."
  opts.separator ""
  opts.separator "OPTIONS:"

  opts.on_tail("-h", "--help", "Show this help.") { puts opts; exit 0 }
}

opts.parse!(ARGV)
if(ARGV.size != 4)
  puts opts
  exit(-1)
end
@syscall_list_file = ARGV[0]
@unistd_dir        = ARGV[1]
@template_dir      = ARGV[2]
@librsc_dir        = ARGV[3]

nr_x86 = Parser::parse_unistd("#{@unistd_dir}/unistd_x86.h")
nr_x86_64 = Parser::parse_unistd("#{@unistd_dir}/unistd_x86_64.h")
nr_x86_64.delete_if{ |el| el.nr == "__NR_syscall_max" } # is not a sycall number
nr_ppc = Parser::parse_unistd("#{@unistd_dir}/unistd_ppc.h")
nr_ppc.delete_if{ |el| el.nr == "__NR_syscalls" } # is not a sycall number


nr_all = nr_x86.merge(nr_x86_64)
nr_all = nr_all.merge(nr_ppc)
# I need to add 2 syscall that are not into the 3 hashes: __RSC_send and __RSC_recv
# In this way I can associate to SYS_SEND and SYS_RECV in architectures like x86 and PPC
nr_all << Syscall::Constant.new("__NR_send", -1, true)
nr_all << Syscall::Constant.new("__NR_recv", -1, true)

nr_all.sort_rsc!
# I set the @nr_all attribute
nr_x86.nr_all = nr_all
nr_x86_64.nr_all = nr_all
nr_ppc.nr_all = nr_all

nr_x86.arch = Syscall::Arch.new(:x86)
nr_x86_64.arch = Syscall::Arch.new(:x86_64)
nr_ppc.arch = Syscall::Arch.new(:ppc)

### I generate the files:
#################################################
# I add the template directory to the library path, because in the template 
# dir can reside some pieces of ruby code used by templates 
$:.unshift @template_dir
template_dir = Dir.new(@template_dir)

umview_rscs = Parser::parse_syslist(@syscall_list_file)
# Setting which syscall are used in umview and which not
nr_x86.set_used_by_umview(umview_rscs)
nr_x86_64.set_used_by_umview(umview_rscs)
nr_ppc.set_used_by_umview(umview_rscs)
nr_all.set_used_by_umview(umview_rscs)
nr_all_umview = nr_all.select{ |el| el.used_by_umview? }

# Template parsing
num_created_files = 0
template_dir.each { |filename|
  abs_path = File::join(template_dir.path, filename)

  if(File.file?(abs_path) && abs_path =~ REGEXP_TEMPLATE_EXT)
    template = File.open(abs_path, "r") { |f| f.read }
    message = ERB.new(template, 0, ">")
    @@librsc_relative_path = nil
    @@filename = nil
    @@overwrite_existing_copy = true
    begin
      result = message.result(get_binding(nr_x86, nr_x86_64, nr_ppc, nr_all))
    rescue Exception => e
      $stderr.puts "Error occured during the parsing of \"#{abs_path}\":"
      $stderr.puts e.backtrace
      raise e
    end
    if(@@librsc_relative_path.nil?) 
      raise "The variable \"@@librsc_relative_path\" is not defined in \"#{abs_path}\""
    end
    if(@@filename.nil?) 
      raise "The variable \"@@filename\" is not defined in \"#{abs_path}\""
    end
    if(@@overwrite_existing_copy.class != TrueClass && @@overwrite_existing_copy.class != FalseClass) 
      raise "The variable \"@@overwrite_existing_copy\" in \"#{abs_path}\" must contain a boolean value."
    end
    
    # I test if output file already exists and if there are some changes from
    # the "result"

    complete_path = "#{@librsc_dir}/#{@@librsc_relative_path}/#{@@filename}"
    
    # I control if the output file already exists
    if(File.file?(complete_path))
      old_file = File.open(complete_path, "r") { |file| file.read }
      # If already exists, I control if it's different from the one that 
      # I'm generating. If yes, I create a backup copy of the old
      # version before generating the file (I do this if, and only if,
      # the @@overwrite_existing_copy is set to true.
      if( old_file != result && @@overwrite_existing_copy )
        #puts "#{complete_path} exists AND old_file != result AND @@overwrite_existing_copy = true"
        # Backup the old version before create the new one
        time = Time.new
        time_str = "#{time.to_f}_#{time.strftime("%d-%b-%y_%H-%M")}"
        backup_name = "#{File.dirname complete_path}/.#{File.basename complete_path}-bak_#{time_str}"
        File.rename(complete_path, backup_name)

        create_file(complete_path,result)
        num_created_files += 1
        $stderr.puts "=> File \"#{complete_path}\": "
        $stderr.puts "| already exists and it's different from the one generated by the template, so"
        $stderr.puts "| a backup copy of the old version was created: \"#{File.basename backup_name}\"."
        $stderr.puts 
      end
    else
      # The file doesn't exist, so I create it
      create_file(complete_path,result)
      num_created_files += 1
    end
  end
}


nr_all.each_umview { |e| puts e } if $DEBUG

puts "Created #{num_created_files} files."
