require_relative '../test_helper'
require 'minitest'
require 'minitest/mock'
require 'rack/test'
require 'rack/session'
require 'bcrypt'

# Gem files, spec indexes and the index APIs need a login session, a
# whitelisted IP, or HTTP Basic credentials. Hostess serves some of these,
# so the gate must run in front of it.
class AccessGateTest < Minitest::Test
  include Rack::Test::Methods

  OUTSIDE_IP = "198.51.100.20".freeze
  GATE_ENV = %w[ADMIN_USER ADMIN_PASS GEMINABOX_IP_WHITELIST GEMINABOX_TRUSTED_PROXIES].freeze

  def setup
    clean_data_dir
    # Server.dependency_cache is memoized per class and clean_data_dir
    # removes its directory, so recreate it.
    Geminabox::Server.dependency_cache.flush
    inject_gems { |builder| builder.gem "foo", version: "1.2.3" }
    @env_backup = ENV.to_h.slice(*GATE_ENV)
    ENV["ADMIN_USER"] = "admin"
    ENV["ADMIN_PASS"] = "secret"
    ENV.delete("GEMINABOX_IP_WHITELIST")
    ENV.delete("GEMINABOX_TRUSTED_PROXIES")
  end

  def teardown
    GATE_ENV.each { |key| ENV.delete(key) }
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

  test "X-Forwarded-For is ignored unless the peer is a trusted proxy" do
    ENV["GEMINABOX_IP_WHITELIST"] = OUTSIDE_IP
    get "/gems/foo-1.2.3.gem", {}, "REMOTE_ADDR" => "172.17.0.1", "HTTP_X_FORWARDED_FOR" => OUTSIDE_IP
    assert_equal 401, last_response.status
  end

  test "a trusted proxy's X-Forwarded-For gives the client IP" do
    ENV["GEMINABOX_IP_WHITELIST"] = OUTSIDE_IP
    ENV["GEMINABOX_TRUSTED_PROXIES"] = "172.17.0.0/16"
    get "/gems/foo-1.2.3.gem", {}, "REMOTE_ADDR" => "172.17.0.1", "HTTP_X_FORWARDED_FOR" => OUTSIDE_IP
    assert last_response.ok?

    # The proxy appends the real peer. A spoofed entry to its left is ignored.
    get "/gems/foo-1.2.3.gem", {}, "REMOTE_ADDR" => "172.17.0.1",
                                   "HTTP_X_FORWARDED_FOR" => "#{OUTSIDE_IP}, 203.0.113.9"
    assert_equal 401, last_response.status
  end

  test "whitelist entries broader than /8 (IPv4) or /32 (IPv6) never match" do
    refute Geminabox::IpWhitelist.valid_entry?("0.0.0.0/0")
    refute Geminabox::IpWhitelist.valid_entry?("1.2.3.4/0")
    refute Geminabox::IpWhitelist.valid_entry?("::/16")
    assert Geminabox::IpWhitelist.valid_entry?("10.0.0.0/8")

    ENV["GEMINABOX_IP_WHITELIST"] = "0.0.0.0/0"
    get "/gems/foo-1.2.3.gem", {}, "REMOTE_ADDR" => OUTSIDE_IP
    assert_equal 401, last_response.status
  end

  test "a correct htpasswd login is cached and a wrong one is not" do
    write_htpasswd([htpasswd_line("alice", "pw-alice")])
    assert Geminabox::Htpasswd.authenticate?("alice", "pw-alice")
    assert Geminabox::Htpasswd.cached?("alice", "pw-alice")

    refute Geminabox::Htpasswd.authenticate?("alice", "wrong")
    refute Geminabox::Htpasswd.cached?("alice", "wrong")
  end

  test "the login cache expires and clears when the file changes" do
    write_htpasswd([htpasswd_line("alice", "pw-alice")])
    assert Geminabox::Htpasswd.authenticate?("alice", "pw-alice")

    later = Geminabox::Htpasswd.now + Geminabox::Htpasswd::CACHE_TTL + 1
    Geminabox::Htpasswd.stub(:now, later) do
      refute Geminabox::Htpasswd.cached?("alice", "pw-alice")
    end

    assert Geminabox::Htpasswd.authenticate?("alice", "pw-alice")
    write_htpasswd([htpasswd_line("alice", "pw-alice")])
    refute Geminabox::Htpasswd.cached?("alice", "pw-alice")
  end

  test "ignored htpasswd lines are logged with the reason" do
    assert_output(nil, /line 2 ignored \(user "md5user"\): not a bcrypt hash.*htpasswd -B .* md5user\n.*line 3 ignored: expected user:hash/m) do
      write_htpasswd(["# comment", "md5user:$apr1$abcdefgh$0123456789abcdefghijkl", "garbage"])
      Geminabox::Htpasswd.users
    end
  end

  test "a rejected Basic login is logged without the password" do
    basic_authorize "mallory", "pw-secret"
    _, err = capture_io { get "/gems/foo-1.2.3.gem", {}, "REMOTE_ADDR" => OUTSIDE_IP }
    assert_match(/Basic auth rejected: user="mallory" ip=#{Regexp.escape(OUTSIDE_IP)} GET \/gems\/foo-1\.2\.3\.gem/, err)
    refute_includes err, "pw-secret"
  end

  test "the unknown-user bcrypt cost is capped" do
    assert_equal Geminabox::Htpasswd::MAX_DUMMY_COST, Geminabox::Htpasswd.dummy_cost([31])
    assert_equal BCrypt::Engine::DEFAULT_COST, Geminabox::Htpasswd.dummy_cost([])
  end

  test "an unknown htpasswd user costs as much bcrypt work as a real one" do
    write_htpasswd(["alice:#{BCrypt::Password.create('pw', cost: 6)}"])
    assert_equal 6, Geminabox::Htpasswd.dummy_hash.cost
  end

  test "a logged-in session downloads and returns to the page it asked for" do
    get "/gems/foo", {}, "REMOTE_ADDR" => OUTSIDE_IP
    assert_match %r{/login\z}, last_response.location

    post "/login", { username: "admin", password: "secret" }, "REMOTE_ADDR" => OUTSIDE_IP
    assert_match %r{/gems/foo\z}, last_response.location

    get "/gems/foo-1.2.3.gem", {}, "REMOTE_ADDR" => OUTSIDE_IP
    assert last_response.ok?
  end

  def write_htpasswd(lines)
    path = File.join(Geminabox.data, "config", "htpasswd")
    FileUtils.mkdir_p(File.dirname(path))
    File.write(path, lines.join("\n") + "\n")
    # Bump mtime so the reload check sees a change within the same second.
    File.utime(Time.now, Time.now + rand(1..1000), path)
  end

  # htpasswd -B writes $2y$. The bcrypt gem writes $2a$ for the same hash.
  def htpasswd_line(user, password)
    "#{user}:#{BCrypt::Password.create(password, cost: BCrypt::Engine::MIN_COST).sub(/\A\$2a\$/, '$2y$')}"
  end

  test "an htpasswd user reaches every read-only client path" do
    write_htpasswd([htpasswd_line("alice", "pw-alice")])
    basic_authorize "alice", "pw-alice"
    CLIENT_PATHS.each do |path|
      get path, {}, "REMOTE_ADDR" => OUTSIDE_IP
      assert last_response.ok?, "on #{path}: #{last_response.status}"
    end
  end

  test "an htpasswd user cannot push, yank, delete, or reindex" do
    write_htpasswd([htpasswd_line("alice", "pw-alice")])
    basic_authorize "alice", "pw-alice"

    post "/api/v1/gems", "x", "REMOTE_ADDR" => OUTSIDE_IP
    assert_equal 401, last_response.status, "push"
    delete "/api/v1/gems/yank", { gem_name: "foo", version: "1.2.3" }, "REMOTE_ADDR" => OUTSIDE_IP
    assert_equal 401, last_response.status, "yank"
    delete "/gems/foo-1.2.3.gem", {}, "REMOTE_ADDR" => OUTSIDE_IP
    assert_equal 401, last_response.status, "delete"
    get "/reindex", {}, "REMOTE_ADDR" => OUTSIDE_IP
    assert_equal 401, last_response.status, "reindex"
    assert File.exist?(File.join(Geminabox.data, "gems", "foo-1.2.3.gem"))
  end

  test "an htpasswd user cannot sign in to the web UI" do
    write_htpasswd([htpasswd_line("alice", "pw-alice")])
    post "/login", { username: "alice", password: "pw-alice" }, "REMOTE_ADDR" => OUTSIDE_IP
    assert_equal 401, last_response.status
  end

  test "a wrong htpasswd password is rejected" do
    write_htpasswd([htpasswd_line("alice", "pw-alice")])
    basic_authorize "alice", "wrong"
    get "/gems/foo-1.2.3.gem", {}, "REMOTE_ADDR" => OUTSIDE_IP
    assert_equal 401, last_response.status
  end

  test "non-bcrypt htpasswd entries are ignored" do
    write_htpasswd([
      "# comment",
      "md5user:$apr1$abcdefgh$0123456789abcdefghijkl",
      "plain:plaintext",
      htpasswd_line("bob", "pw-bob")
    ])
    basic_authorize "plain", "plaintext"
    get "/gems/foo-1.2.3.gem", {}, "REMOTE_ADDR" => OUTSIDE_IP
    assert_equal 401, last_response.status

    basic_authorize "bob", "pw-bob"
    get "/gems/foo-1.2.3.gem", {}, "REMOTE_ADDR" => OUTSIDE_IP
    assert last_response.ok?
  end

  test "htpasswd changes apply without a restart" do
    write_htpasswd([htpasswd_line("alice", "pw-alice")])
    basic_authorize "carol", "pw-carol"
    get "/gems/foo-1.2.3.gem", {}, "REMOTE_ADDR" => OUTSIDE_IP
    assert_equal 401, last_response.status

    write_htpasswd([htpasswd_line("carol", "pw-carol")])
    get "/gems/foo-1.2.3.gem", {}, "REMOTE_ADDR" => OUTSIDE_IP
    assert last_response.ok?

    write_htpasswd([])
    get "/gems/foo-1.2.3.gem", {}, "REMOTE_ADDR" => OUTSIDE_IP
    assert_equal 401, last_response.status
  end

  test "a wrong password does not log in" do
    post "/login", { username: "admin", password: "nope" }, "REMOTE_ADDR" => OUTSIDE_IP
    assert_equal 401, last_response.status
    get "/", {}, "REMOTE_ADDR" => OUTSIDE_IP
    assert_match %r{/login\z}, last_response.location
  end
end
