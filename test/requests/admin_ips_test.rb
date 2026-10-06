require_relative '../test_helper'
require 'minitest'
require 'rack/test'
require 'rack/session'
require 'nokogiri'
require 'yaml'

# The IP whitelist bypasses login, so every /admin route must require a
# logged-in session, reject entries that are not IPs, and escape what it
# renders.
class AdminIpsTest < Minitest::Test
  include Rack::Test::Methods

  CLIENT_IP = "203.0.113.9".freeze

  def setup
    clean_data_dir
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

  def whitelist_file
    File.join(Geminabox.data, "config", "ip_whitelist.yml")
  end

  def stored_entries
    File.exist?(whitelist_file) ? YAML.load_file(whitelist_file) : []
  end

  def log_in
    post "/login", { username: "admin", password: "secret" }, "REMOTE_ADDR" => CLIENT_IP
    assert last_response.redirect?, "login failed: #{last_response.status}"
  end

  test "anonymous POST cannot add an entry" do
    post "/admin/ips", { entry: CLIENT_IP }, "REMOTE_ADDR" => CLIENT_IP
    assert last_response.redirect?
    assert_match %r{/login\z}, last_response.location
    assert_empty stored_entries
  end

  test "anonymous POST cannot remove an entry" do
    FileUtils.mkdir_p(File.dirname(whitelist_file))
    File.write(whitelist_file, ["10.0.0.1"].to_yaml)

    post "/admin/ips/delete", { entry: "10.0.0.1" }, "REMOTE_ADDR" => CLIENT_IP
    assert_match %r{/login\z}, last_response.location
    assert_equal ["10.0.0.1"], stored_entries
  end

  test "a whitelisted IP without a session cannot change the whitelist" do
    ENV["GEMINABOX_IP_WHITELIST"] = CLIENT_IP

    post "/admin/ips", { entry: "198.51.100.7" }, "REMOTE_ADDR" => CLIENT_IP
    assert_match %r{/login\z}, last_response.location
    assert_empty stored_entries

    get "/admin/ips", {}, "REMOTE_ADDR" => CLIENT_IP
    assert_match %r{/login\z}, last_response.location
  end

  test "a logged-in user can add an IP and a CIDR range" do
    log_in
    post "/admin/ips", { entry: "198.51.100.7" }, "REMOTE_ADDR" => CLIENT_IP
    post "/admin/ips", { entry: "10.0.0.0/8" }, "REMOTE_ADDR" => CLIENT_IP
    assert_equal ["10.0.0.0/8", "198.51.100.7"], stored_entries
  end

  test "a logged-in user cannot add an entry that is not an IP" do
    log_in
    post "/admin/ips", { entry: "<script>alert(1)</script>" }, "REMOTE_ADDR" => CLIENT_IP
    assert_empty stored_entries

    get "/admin/ips", {}, "REMOTE_ADDR" => CLIENT_IP
    assert last_response.ok?
    assert_includes last_response.body, "Not an IP address or CIDR range"
    refute_includes last_response.body, "<script>alert(1)</script>"
  end

  test "stored entries render escaped with no inline script" do
    FileUtils.mkdir_p(File.dirname(whitelist_file))
    File.write(whitelist_file, ["x');alert(1);//<img src=x onerror=alert(2)>"].to_yaml)

    log_in
    get "/admin/ips", {}, "REMOTE_ADDR" => CLIENT_IP
    assert last_response.ok?

    doc = Nokogiri::HTML(last_response.body)
    assert_empty doc.css("img")
    assert_empty doc.css("[onsubmit]")
    form = doc.at_css("form.remove-ip-form")
    assert_equal "x');alert(1);//<img src=x onerror=alert(2)>", form["data-entry"]
  end
end
