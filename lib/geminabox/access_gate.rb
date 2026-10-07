# frozen_string_literal: true

require 'rack/auth/basic'

module Geminabox
  # Lets a request through only with a logged-in session, a whitelisted IP,
  # or valid HTTP Basic credentials. Server mounts it in front of Hostess, so
  # gem files and spec indexes are gated too.
  #
  # Basic credentials are either ADMIN_USER/ADMIN_PASS (full access) or an
  # htpasswd user (read-only: GET and HEAD on READ_ONLY_PATHS). Repeated
  # failed Basic logins from one IP get 429 (see LoginThrottle).
  class AccessGate
    OPEN_PATHS = [
      %r{\A/login\z},
      %r{\A/logout\z},
      %r{\A/master\.js\z},
      %r{\A/favicon\.ico\z},
      %r{\A/robots\.txt\z}
    ].freeze

    # Paths that gem clients fetch. These get a 401 Basic challenge, never a
    # redirect to the HTML login page.
    CLIENT_PATHS = [
      %r{\A/gems/.+\.gem\z},
      %r{\A/api/},
      %r{\A/versions\z},
      %r{\A/names\z},
      %r{\A/info/},
      %r{\A/(latest_|prerelease_)?specs\.4\.8(\.gz)?\z},
      %r{\A/quick/},
      %r{\A/atom\.xml\z},
      %r{\A/reindex\z}
    ].freeze

    # Client paths an htpasswd user can fetch. /reindex is left out because
    # it rewrites the index.
    READ_ONLY_PATHS = (CLIENT_PATHS - [%r{\A/reindex\z}]).freeze

    def initialize(app)
      @app = app
    end

    def call(env)
      request = Rack::Request.new(env)
      path = request.path_info
      return @app.call(env) if OPEN_PATHS.any? { |pattern| pattern.match?(path) }

      ip = IpWhitelist.client_ip(env)
      return @app.call(env) if request.session[:logged_in] || IpWhitelist.include?(ip)
      if (seconds = LoginThrottle.retry_after(ip))
        return LoginThrottle.too_many_response(ip, seconds)
      end
      return @app.call(env) if basic_auth_valid?(request, env, ip)

      if CLIENT_PATHS.any? { |pattern| pattern.match?(path) }
        challenge
      else
        request.session[:return_to] = request.fullpath if request.get?
        [302, { "location" => "#{request.base_url}#{request.script_name}/login" }, []]
      end
    end

    private

    def basic_auth_valid?(request, env, ip)
      auth = Rack::Auth::Basic::Request.new(env)
      return false unless auth.provided? && auth.basic?

      return true if Server.admin_credentials_match?(*auth.credentials)
      return true if read_only_request?(request) && Htpasswd.authenticate?(*auth.credentials)

      # The username is client input. inspect escapes control characters, so
      # it cannot forge log lines. The password is never logged.
      warn "[geminabox] Basic auth rejected: user=#{auth.username.to_s.inspect} " \
           "ip=#{ip} #{request.request_method} #{request.path_info.inspect[1..-2]}"
      LoginThrottle.record_failure(ip)
      false
    end

    def read_only_request?(request)
      (request.get? || request.head?) &&
        READ_ONLY_PATHS.any? { |pattern| pattern.match?(request.path_info) }
    end

    def challenge
      [
        401,
        { "content-type" => "text/plain", "www-authenticate" => 'Basic realm="Gem in a Box"' },
        ["Authentication required: log in, connect from a whitelisted IP, or send HTTP Basic credentials.\n"]
      ]
    end
  end
end
