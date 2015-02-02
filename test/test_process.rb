require 'minitest/autorun'
require_relative '../ruby_ptrace'

class TestProcess < MiniTest::Unit::TestCase
  def test_that_it_can_attach_to_processes_and_change_data
    proc = RubyPtrace::Process.new
    cpid = Process.spawn('ls')
    puts "PROCESS ID: #{cpid}"
    proc.attach(cpid)
    proc.stop
    proc.set_data(0x08048000, 0xDEAD)
    assert_equal 0xDEAD, proc.get_data(0x08048000)
    proc.detach
  end
  
  def test_that_it_can_read_register_info
    
  end
end

