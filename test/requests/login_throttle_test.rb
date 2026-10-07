require_relative '../test_helper'
require 'minitest'
require 'minitest/mock'
require 'rack/test'
require 'rack/session'
require 'bcrypt'

# Repeated failed logins from one IP get 429 until the block ends. The
# gate's Basic auth, the /login form, and config.ru's push routes share
# one count per IP.
class LoginThrottleTest < Minitest::Test
  include Rack::Test::Methods

  ATTACKER_IP = "198.51.100.40".freeze
  OTHER_IP = "198.51.100.41".freeze
  THROTTLE_ENV = %w[ADMIN_USER ADMIN_PASS GEMINABOX_IP_WHITELIST
                    GEMINABOX_AUTH_MAX_FAILURES GEMINABOX_AUTH_BLOCK_SECONDS].freeze

  def setup
    clean_data_dir
    Geminabox::Server.dependency_cache.flush
    inject_gems { |builder| builder.gem "foo", version: "1.2.3" }
    @env_backup = ENV.to_h.slice(*THROTTLE_ENV)
    THROTTLE_ENV.each { |key| ENV.delete(key) }
    ENV["ADMIN_USER"] = "admin"
    ENV["ADMIN_PASS"] = "secret"
    ENV["GEMINABOX_AUTH_MAX_FAILURES"] = "3"
    ENV["GEMINABOX_AUTH_BLOCK_SECONDS"] = "60"
  end

  def teardown
    THROTTLE_ENV.each { |key| ENV.delete(key) }
    @env_backup.each { |key, value| ENV[key] = value }
  end

  def app
    @app ||= Rack::Builder.new do
      use Rack::Session::Pool
      run Geminabox::Server
    end.to_app
  end

  def fail_basic(ip, times)
    basic_authorize "admin", "wrong"
    times.times do
      capture_io { get "/gems/foo-1.2.3.gem", {}, "REMOTE_ADDR" => ip }
    end
  end

  test "an IP is blocked after too many failed Basic logins, even with correct credentials" do
    fail_basic(ATTACKER_IP, 3)
    assert_equal 401, last_response.status

    basic_authorize "admin", "secret"
    get "/gems/foo-1.2.3.gem", {}, "REMOTE_ADDR" => ATTACKER_IP
    assert_equal 429, last_response.status
    assert_operator last_response.headers["retry-after"].to_i, :>, 0

    get "/gems/foo-1.2.3.gem", {}, "REMOTE_ADDR" => OTHER_IP
    assert last_response.ok?
  end

  test "a blocked request runs no credential check and writes no rejected line" do
    fail_basic(ATTACKER_IP, 3)
    basic_authorize "admin", "wrong"
    Geminabox::Server.stub(:admin_credentials_match?, ->(*) { flunk "credentials checked while blocked" }) do
      _, err = capture_io { get "/gems/foo-1.2.3.gem", {}, "REMOTE_ADDR" => ATTACKER_IP }
      assert_equal 429, last_response.status
      refute_match(/Basic auth rejected/, err)
    end
  end

  test "the block ends after GEMINABOX_AUTH_BLOCK_SECONDS" do
    fail_basic(ATTACKER_IP, 3)
    later = Geminabox::LoginThrottle.now + 61
    Geminabox::LoginThrottle.stub(:now, later) do
      basic_authorize "admin", "secret"
      get "/gems/foo-1.2.3.gem", {}, "REMOTE_ADDR" => ATTACKER_IP
      assert last_response.ok?
    end
  end

  test "a successful login does not clear earlier failures" do
    # A valid low-privilege htpasswd login must not reset failed admin
    # guesses, or guessing never hits the limit.
    path = File.join(Geminabox.data, "config", "htpasswd")
    FileUtils.mkdir_p(File.dirname(path))
    File.write(path, "dev:#{BCrypt::Password.create('pw-dev', cost: BCrypt::Engine::MIN_COST)}\n")

    fail_basic(ATTACKER_IP, 2)
    basic_authorize "dev", "pw-dev"
    get "/gems/foo-1.2.3.gem", {}, "REMOTE_ADDR" => ATTACKER_IP
    assert last_response.ok?

    fail_basic(ATTACKER_IP, 1)
    basic_authorize "dev", "pw-dev"
    get "/gems/foo-1.2.3.gem", {}, "REMOTE_ADDR" => ATTACKER_IP
    assert_equal 429, last_response.status
  end

  test "failed form logins count, and a blocked form login gets 429" do
    3.times { post "/login", { username: "admin", password: "nope" }, "REMOTE_ADDR" => ATTACKER_IP }
    post "/login", { username: "admin", password: "secret" }, "REMOTE_ADDR" => ATTACKER_IP
    assert_equal 429, last_response.status
    assert_includes last_response.body, "Too many failed logins"
  end

  test "a whitelisted IP is never blocked" do
    ENV["GEMINABOX_IP_WHITELIST"] = ATTACKER_IP
    fail_basic(ATTACKER_IP, 5)
    assert last_response.ok?
  end

  test "the block is logged once" do
    basic_authorize "admin", "wrong"
    _, err = capture_io do
      5.times { get "/gems/foo-1.2.3.gem", {}, "REMOTE_ADDR" => ATTACKER_IP }
    end
    assert_equal 1, err.scan(/ip=#{Regexp.escape(ATTACKER_IP)} blocked for 60s after 3 failed logins/).size
  end

  test "an invalid limit falls back to the default" do
    ENV["GEMINABOX_AUTH_MAX_FAILURES"] = "lots"
    assert_equal Geminabox::LoginThrottle::DEFAULT_MAX_FAILURES, Geminabox::LoginThrottle.max_failures
  end
end
