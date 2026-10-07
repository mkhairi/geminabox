require_relative '../test_helper'

# Each integration test forks a server. A server that outlives its test
# keeps its port and memory until someone kills it by hand.
class TestServerShutdownTest < Geminabox::TestCase
  test "stop_app! leaves no server process behind" do
    pid = @app_server
    stop_app!
    @app_server = nil

    assert server_gone?(pid, within: 3), "server #{pid} still runs after stop_app!"
  end

  private

  def server_gone?(pid, within:)
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + within
    until Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline
      return true if Process.waitpid(pid, Process::WNOHANG)
      sleep 0.1
    end
    Process.kill(9, pid)
    false
  rescue Errno::ECHILD
    true
  end
end
