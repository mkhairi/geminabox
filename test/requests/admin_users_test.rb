require_relative '../test_helper'
require 'minitest'
require 'minitest/mock'
require 'rack/test'
require 'rack/session'
require 'nokogiri'
require 'bcrypt'

# /admin/users manages the htpasswd install-only users. Only a logged-in
# admin can list, add, reset, or remove them.
class AdminUsersTest < Minitest::Test
  include Rack::Test::Methods

  CLIENT_IP = "203.0.113.19".freeze

  def setup
    clean_data_dir
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

  def htpasswd_file
    File.join(Geminabox.data, "config", "htpasswd")
  end

  def htpasswd_lines
    File.exist?(htpasswd_file) ? File.readlines(htpasswd_file, chomp: true) : []
  end

  def log_in
    post "/login", { username: "admin", password: "secret" }, "REMOTE_ADDR" => CLIENT_IP
    assert last_response.redirect?, "login failed: #{last_response.status}"
  end

  def shown_password
    Nokogiri::HTML(last_response.body).at_css("[data-new-password]")&.text
  end

  test "anonymous requests cannot list, add, reset, or remove users" do
    get "/admin/users", {}, "REMOTE_ADDR" => CLIENT_IP
    assert_match %r{/login\z}, last_response.location
    post "/admin/users", { username: "alice" }, "REMOTE_ADDR" => CLIENT_IP
    assert_match %r{/login\z}, last_response.location
    post "/admin/users/reset", { username: "alice" }, "REMOTE_ADDR" => CLIENT_IP
    assert_match %r{/login\z}, last_response.location
    post "/admin/users/delete", { username: "alice" }, "REMOTE_ADDR" => CLIENT_IP
    assert_match %r{/login\z}, last_response.location
    assert_empty htpasswd_lines
  end

  test "adding a user with no password generates one, shows it once, and it works" do
    log_in
    _, err = capture_io { post "/admin/users", { username: "alice" }, "REMOTE_ADDR" => CLIENT_IP }
    assert last_response.ok?
    assert_equal "no-store", last_response.headers["cache-control"]
    password = shown_password
    refute_nil password, "generated password not shown"
    assert_operator password.length, :>=, 20
    assert Geminabox::Htpasswd.authenticate?("alice", password)
    assert_match(/\Aalice:\$2[aby]\$/, htpasswd_lines.last)
    assert_match(/htpasswd user added: "alice" by "admin"/, err)
    refute_includes err, password

    get "/admin/users", {}, "REMOTE_ADDR" => CLIENT_IP
    assert_nil shown_password, "password shown again after reload"
    assert_includes last_response.body, "alice"
  end

  test "a new user can download gems with Basic auth right away" do
    log_in
    capture_io { post "/admin/users", { username: "alice" }, "REMOTE_ADDR" => CLIENT_IP }
    password = shown_password

    clear_cookies
    basic_authorize "alice", password
    get "/gems/foo-1.2.3.gem", {}, "REMOTE_ADDR" => CLIENT_IP
    assert last_response.ok?
  end

  test "an admin-chosen password must be at least 12 characters" do
    log_in
    post "/admin/users", { username: "alice", password: "short" }, "REMOTE_ADDR" => CLIENT_IP
    assert_equal 422, last_response.status
    assert_includes last_response.body, "at least 12 characters"
    assert_empty htpasswd_lines

    capture_io { post "/admin/users", { username: "alice", password: "long-enough-pw" }, "REMOTE_ADDR" => CLIENT_IP }
    assert last_response.ok?
    assert_nil shown_password, "an admin-chosen password is not echoed"
    assert Geminabox::Htpasswd.authenticate?("alice", "long-enough-pw")
  end

  test "invalid and duplicate usernames are rejected" do
    log_in
    ["bad:name", "a b", "<script>", "", "x" * 65].each do |name|
      post "/admin/users", { username: name }, "REMOTE_ADDR" => CLIENT_IP
      assert_equal 422, last_response.status, "accepted #{name.inspect}"
    end
    assert_empty htpasswd_lines

    capture_io { post "/admin/users", { username: "alice" }, "REMOTE_ADDR" => CLIENT_IP }
    post "/admin/users", { username: "alice" }, "REMOTE_ADDR" => CLIENT_IP
    assert_equal 422, last_response.status
    assert_includes last_response.body, "already exists"
    assert_equal 1, htpasswd_lines.size
  end

  test "reset replaces the password" do
    log_in
    capture_io { post "/admin/users", { username: "alice", password: "first-password-1" }, "REMOTE_ADDR" => CLIENT_IP }
    capture_io { post "/admin/users/reset", { username: "alice" }, "REMOTE_ADDR" => CLIENT_IP }
    assert last_response.ok?
    new_password = shown_password
    refute_nil new_password
    refute Geminabox::Htpasswd.authenticate?("alice", "first-password-1")
    assert Geminabox::Htpasswd.authenticate?("alice", new_password)

    post "/admin/users/reset", { username: "nobody" }, "REMOTE_ADDR" => CLIENT_IP
    assert_equal 422, last_response.status
  end

  test "remove deletes only that user and keeps other lines" do
    FileUtils.mkdir_p(File.dirname(htpasswd_file))
    hash = BCrypt::Password.create("pw-bob-123456", cost: BCrypt::Engine::MIN_COST)
    File.write(htpasswd_file, "# team users\nbob:#{hash}\nalice:#{hash}\nlegacy:$apr1$abc$def\n")
    log_in

    capture_io { post "/admin/users/delete", { username: "alice" }, "REMOTE_ADDR" => CLIENT_IP }
    assert last_response.redirect?
    assert_equal ["# team users", "bob:#{hash}", "legacy:$apr1$abc$def"], htpasswd_lines
    assert Geminabox::Htpasswd.authenticate?("bob", "pw-bob-123456")
  end

  test "reset and remove act on every line for the user, however it is written" do
    FileUtils.mkdir_p(File.dirname(htpasswd_file))
    old = BCrypt::Password.create("old-password-1", cost: BCrypt::Engine::MIN_COST)
    File.write(htpasswd_file, "alice:#{old}\n  alice:#{old}  \r\nbob:#{old}\n")
    log_in

    capture_io { post "/admin/users/reset", { username: "alice", password: "new-password-12" }, "REMOTE_ADDR" => CLIENT_IP }
    refute Geminabox::Htpasswd.authenticate?("alice", "old-password-1")
    assert Geminabox::Htpasswd.authenticate?("alice", "new-password-12")
    assert_equal 1, htpasswd_lines.count { |l| l.strip.start_with?("alice:") }

    File.write(htpasswd_file, "alice:#{old}\n  alice:#{old}\nbob:#{old}\n")
    capture_io { post "/admin/users/delete", { username: "alice" }, "REMOTE_ADDR" => CLIENT_IP }
    refute Geminabox::Htpasswd.authenticate?("alice", "old-password-1")
    assert_equal ["bob:#{old}"], htpasswd_lines
  end

  test "the list escapes usernames from a hand-edited file" do
    FileUtils.mkdir_p(File.dirname(htpasswd_file))
    hash = BCrypt::Password.create("pw", cost: BCrypt::Engine::MIN_COST)
    File.write(htpasswd_file, "<img src=x>:#{hash}\n")
    log_in

    get "/admin/users", {}, "REMOTE_ADDR" => CLIENT_IP
    assert last_response.ok?
    refute_includes last_response.body, "<img src=x>"
    assert_includes last_response.body, "&lt;img src=x&gt;"
  end

  test "a write error is shown, not raised" do
    FileUtils.mkdir_p(File.dirname(htpasswd_file))
    log_in
    Geminabox::Htpasswd.stub(:write_lines, ->(*) { raise Errno::EACCES, htpasswd_file }) do
      post "/admin/users", { username: "alice" }, "REMOTE_ADDR" => CLIENT_IP
    end
    assert_equal 500, last_response.status
    assert_includes last_response.body, "Cannot write"
  end
end
