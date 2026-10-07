$:.unshift(File.expand_path(File.join(File.dirname(__FILE__), "lib")))
require "geminabox"
require "rack/auth/basic"
require "rack/request"

class GeminaboxProtectedRoutes
  PROTECTED_RULES = [
    { methods: %w[GET POST], path: %r{\A/upload/?\z} },
    { methods: %w[POST], path: %r{\A/api/v1/gems/?\z} },
    { methods: %w[DELETE POST], path: %r{\A/gems/.*\.gem\z} },
    { methods: %w[DELETE POST], path: %r{\A/api/v1/gems/yank/?\z} },
    # Rebuilds the whole index. A whitelisted IP may download, not rebuild.
    { methods: %w[GET POST], path: %r{\A/reindex/?\z} }
  ].freeze

  def initialize(app, username:, password:)
    @app = app
    @username = username
    @password = password
  end

  def call(env)
    request = Rack::Request.new(env)
    return @app.call(env) unless protected_request?(request)

    ip = Geminabox::IpWhitelist.client_ip(env)
    if (seconds = Geminabox::LoginThrottle.retry_after(ip))
      return Geminabox::LoginThrottle.too_many_response(ip, seconds)
    end

    return @app.call(env) if authorized?(env)

    # A request without credentials is a client asking for the challenge,
    # not a failed login.
    Geminabox::LoginThrottle.record_failure(ip) if Rack::Auth::Basic::Request.new(env).provided?
    unauthorized_response
  end

  private

  def protected_request?(request)
    PROTECTED_RULES.any? do |rule|
      rule[:methods].include?(request.request_method) &&
        rule[:path].match?(request.path_info)
    end
  end

  def authorized?(env)
    auth = Rack::Auth::Basic::Request.new(env)
    if auth.provided? && auth.basic? && credentials_match?(*auth.credentials)
      env["REMOTE_USER"] = @username
      true
    else
      false
    end
  end

  def credentials_match?(username, password)
    user_ok = Rack::Utils.secure_compare(username.to_s, @username)
    pass_ok = Rack::Utils.secure_compare(password.to_s, @password)
    user_ok && pass_ok
  end

  def unauthorized_response
    [
      401,
      { "WWW-Authenticate" => 'Basic realm="Restricted Area"' },
      ["Authorization Required"]
    ]
  end
end

Geminabox.data = ENV.fetch("GEMINABOX_DATA", "/data")

username = ENV["ADMIN_USER"]
password = ENV["ADMIN_PASS"]
session_secret = ENV["SESSION_SECRET"].to_s

if username.to_s.empty? || password.to_s.empty?
  raise "ADMIN_USER and ADMIN_PASS must be set for protected routes."
end

if session_secret.length < 64
  raise "SESSION_SECRET must be set to at least 64 characters. Generate one with: openssl rand -hex 64"
end

use GeminaboxProtectedRoutes, username: username, password: password
use Rack::Session::Cookie,
    key: "geminabox.session",
    secret: session_secret,
    same_site: :lax,
    httponly: true,
    expire_after: 1000 # sec
use Rack::Protection
# Browser forms carry a session token. CLI clients (gem push, gem inabox,
# bundler) send an Authorization header and no session, so they skip it.
# Rack::Protection's Origin check above still covers cross-site browser
# requests that carry cached Basic credentials.
use Rack::Protection::AuthenticityToken,
    allow_if: ->(env) { env.key?("HTTP_AUTHORIZATION") }

run Geminabox::Server
