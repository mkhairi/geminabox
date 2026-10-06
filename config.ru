$:.unshift(File.expand_path(File.join(File.dirname(__FILE__), "lib")))
require "geminabox"
require "rack/auth/basic"
require "rack/request"

class GeminaboxProtectedRoutes
  PROTECTED_RULES = [
    { methods: %w[GET POST], path: %r{\A/upload/?\z} },
    { methods: %w[POST], path: %r{\A/api/v1/gems/?\z} },
    { methods: %w[DELETE POST], path: %r{\A/gems/.*\.gem\z} },
    { methods: %w[DELETE POST], path: %r{\A/api/v1/gems/yank/?\z} }
  ].freeze

  def initialize(app, username:, password:)
    @app = app
    @username = username
    @password = password
  end

  def call(env)
    request = Rack::Request.new(env)
    if protected_request?(request)
      return unauthorized_response unless authorized?(env)
    end

    @app.call(env)
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
    if auth.provided? && auth.basic? && auth.credentials == [@username, @password]
      env["REMOTE_USER"] = @username
      true
    else
      false
    end
  end

  def unauthorized_response
    [
      401,
      { "WWW-Authenticate" => 'Basic realm="Restricted Area"' },
      ["Authorization Required"]
    ]
  end
end

Geminabox.rubygems_proxy = false
Geminabox.data = "/data"

username = ENV["ADMIN_USER"]
password = ENV["ADMIN_PASS"]

if username.to_s.empty? || password.to_s.empty?
  raise "ADMIN_USER and ADMIN_PASS must be set for protected routes."
end

Geminabox::Server.set :ui_username, username
Geminabox::Server.set :ui_password, password

use GeminaboxProtectedRoutes, username: username, password: password
use Rack::Session::Pool, expire_after: 1000 # sec
use Rack::Protection

run Geminabox::Server
