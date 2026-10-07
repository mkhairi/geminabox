require_relative '../test_helper'
require 'minitest'
require 'rack/test'
require 'rack/builder'
require 'nokogiri'

# config.ru wires signed cookie sessions, the CSRF token check, and the data
# directory. These tests boot the real file.
class ConfigRuTest < Minitest::Test
  include Rack::Test::Methods

  CONFIG_RU = File.expand_path("../../config.ru", __dir__)
  ENV_KEYS = %w[ADMIN_USER ADMIN_PASS SESSION_SECRET GEMINABOX_DATA GEMINABOX_IP_WHITELIST].freeze
  OUTSIDE_IP = "198.51.100.30".freeze

  def setup
    clean_data_dir
    @data_backup = Geminabox.data
    @env_backup = ENV.to_h.slice(*ENV_KEYS)
    ENV["ADMIN_USER"] = "admin"
    ENV["ADMIN_PASS"] = "secret"
    ENV["SESSION_SECRET"] = "s" * 64
    ENV["GEMINABOX_DATA"] = @data_backup
    ENV.delete("GEMINABOX_IP_WHITELIST")
  end

  def teardown
    ENV_KEYS.each { |key| ENV.delete(key) }
    @env_backup.each { |key, value| ENV[key] = value }
    Geminabox.data = @data_backup
  end

  def boot
    app = Rack::Builder.parse_file(CONFIG_RU)
    app.is_a?(Array) ? app.first : app
  end

  def app
    @app ||= boot
  end

  def login_token
    get "/login", {}, "REMOTE_ADDR" => OUTSIDE_IP
    Nokogiri::HTML(last_response.body).at_css("input[name=authenticity_token]")["value"]
  end

  test "boot refuses a missing SESSION_SECRET" do
    ENV.delete("SESSION_SECRET")
    error = assert_raises(RuntimeError) { boot }
    assert_match(/SESSION_SECRET/, error.message)
  end

  test "boot refuses a SESSION_SECRET shorter than 64 characters" do
    ENV["SESSION_SECRET"] = "short"
    assert_raises(RuntimeError) { boot }
  end

  test "GEMINABOX_DATA sets the data directory" do
    ENV["GEMINABOX_DATA"] = "/tmp/geminabox-config-ru-test"
    boot
    assert_equal "/tmp/geminabox-config-ru-test", Geminabox.data
  end

  test "login without a CSRF token is refused" do
    post "/login", { username: "admin", password: "secret" }, "REMOTE_ADDR" => OUTSIDE_IP
    assert_equal 403, last_response.status
  end

  test "login with the form's CSRF token succeeds and the session persists" do
    token = login_token
    post "/login", { username: "admin", password: "secret", authenticity_token: token },
         "REMOTE_ADDR" => OUTSIDE_IP
    assert last_response.redirect?
    assert_match(/geminabox\.session=.*samesite=lax/i, last_response.headers["set-cookie"])

    get "/", {}, "REMOTE_ADDR" => OUTSIDE_IP
    assert last_response.ok?
  end

  test "CLI clients with Basic auth skip the CSRF token" do
    basic_authorize "admin", "secret"
    post "/api/v1/gems", "not a gem", "REMOTE_ADDR" => OUTSIDE_IP, "CONTENT_TYPE" => "application/octet-stream"
    refute_equal 403, last_response.status
  end
end
