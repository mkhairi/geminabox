require_relative '../test_helper'
require 'minitest'
require 'rack/test'
require 'rack/session'

# Gem files, spec indexes and the index APIs need a login session, a
# whitelisted IP, or HTTP Basic credentials. Hostess serves some of these,
# so the gate must run in front of it.
class AccessGateTest < Minitest::Test
  include Rack::Test::Methods

  OUTSIDE_IP = "198.51.100.20".freeze

  def setup
    clean_data_dir
    # Server.dependency_cache is memoized per class and clean_data_dir
    # removes its directory, so recreate it.
    Geminabox::Server.dependency_cache.flush
    inject_gems { |builder| builder.gem "foo", version: "1.2.3" }
    @env_backup = ENV.to_h.slice("ADMIN_USER", "ADMIN_PASS", "GEMINABOX_IP_WHITELIST")
    ENV["ADMIN_USER"] = "admin"
    ENV["ADMIN_PASS"] = "secret"
    ENV.delete("GEMINABOX_IP_WHITELIST")
  end

  def teardown
    %w[ADMIN_USER ADMIN_PASS GEMINABOX_IP_WHITELIST].each { |key| ENV.delete(key) }
    @env_backup.each { |key, value| ENV[key] = value }
  end

  def app
    @app ||= Rack::Builder.new do
      use Rack::Session::Pool
      run Geminabox::Server
    end.to_app
  end

  CLIENT_PATHS = %w[
    /gems/foo-1.2.3.gem
    /specs.4.8.gz
    /latest_specs.4.8.gz
    /prerelease_specs.4.8.gz
    /quick/Marshal.4.8/foo-1.2.3.gemspec.rz
    /versions
    /names
    /info/foo
    /api/v1/dependencies?gems=foo
    /atom.xml
  ].freeze

  test "anonymous clients get a 401 Basic challenge on every client path" do
    CLIENT_PATHS.each do |path|
      get path, {}, "REMOTE_ADDR" => OUTSIDE_IP
      assert_equal 401, last_response.status, "on #{path}"
      assert_match(/\ABasic /, last_response.headers["www-authenticate"], "on #{path}")
    end
  end

  test "anonymous page views redirect to login" do
    %w[/ /guide /gems/foo].each do |path|
      get path, {}, "REMOTE_ADDR" => OUTSIDE_IP
      assert last_response.redirect?, "on #{path}"
      assert_match %r{/login\z}, last_response.location, "on #{path}"
    end
  end

  test "the login page stays reachable" do
    get "/login", {}, "REMOTE_ADDR" => OUTSIDE_IP
    assert last_response.ok?
  end

  test "valid Basic credentials reach every client path" do
    basic_authorize "admin", "secret"
    CLIENT_PATHS.each do |path|
      get path, {}, "REMOTE_ADDR" => OUTSIDE_IP
      assert last_response.ok?, "on #{path}: #{last_response.status}"
    end
  end

  test "wrong Basic credentials are rejected" do
    basic_authorize "admin", "wrong"
    get "/gems/foo-1.2.3.gem", {}, "REMOTE_ADDR" => OUTSIDE_IP
    assert_equal 401, last_response.status
  end

  test "a whitelisted IP downloads without credentials" do
    ENV["GEMINABOX_IP_WHITELIST"] = OUTSIDE_IP
    get "/gems/foo-1.2.3.gem", {}, "REMOTE_ADDR" => OUTSIDE_IP
    assert last_response.ok?
  end

  test "a logged-in session downloads and returns to the page it asked for" do
    get "/gems/foo", {}, "REMOTE_ADDR" => OUTSIDE_IP
    assert_match %r{/login\z}, last_response.location

    post "/login", { username: "admin", password: "secret" }, "REMOTE_ADDR" => OUTSIDE_IP
    assert_match %r{/gems/foo\z}, last_response.location

    get "/gems/foo-1.2.3.gem", {}, "REMOTE_ADDR" => OUTSIDE_IP
    assert last_response.ok?
  end

  test "a wrong password does not log in" do
    post "/login", { username: "admin", password: "nope" }, "REMOTE_ADDR" => OUTSIDE_IP
    assert_equal 401, last_response.status
    get "/", {}, "REMOTE_ADDR" => OUTSIDE_IP
    assert_match %r{/login\z}, last_response.location
  end
end
