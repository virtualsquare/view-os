#   
#   This is part of RSC file generator program
#
#   Rekefile.rb: a ruby Makefile to manage the project
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

require 'rake/clean'
CLEAN.add('doc')

task :default => [:doc]

desc "Create the library's documentation"
task :doc do
  sh "rdoc"
end

desc "Execute the library tests"
task :test  do
  test_dir  = 'tests'
  tests_list = ['c_test.rb']

  tests_list_complete_path =  tests_list.collect{|d| File::join(test_dir, d)}
  tests_list_complete_path.each do |test_path|
    ruby test_path
  end
end
