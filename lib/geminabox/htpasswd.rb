# frozen_string_literal: true

require 'bcrypt'
require 'openssl'
require 'securerandom'

module Geminabox
  # Read-only users from an htpasswd file, created with `htpasswd -B`.
  # Only bcrypt entries ($2y$, $2a$, $2b$) are accepted. Other lines are
  # skipped with a warning on stderr. The file is re-read when its mtime
  # changes.
  #
  # A correct login is cached for CACHE_TTL seconds, so a bundle install
  # does not run one bcrypt check per request. The cache holds only an HMAC
  # of user and password under a per-process key. It clears when the file
  # changes.
  #
  # Path: GEMINABOX_HTPASSWD, or <Geminabox.data>/config/htpasswd.
  module Htpasswd
    BCRYPT_PREFIX = /\A\$2[aby]\$/
    # Upper bound for the unknown-user hash. One entry with a huge cost must
    # not make every unknown-user request that slow.
    MAX_DUMMY_COST = 12
    CACHE_TTL = 300
    # The cache empties when it reaches this size, so it stays bounded.
    CACHE_MAX = 1000

    @mutex = Mutex.new
    @dummy_hashes = {}
    @cache = { path: nil, mtime: nil, users: {} }
    @verified = {}
    @cache_key = SecureRandom.bytes(32)

    module_function

    def authenticate?(username, password)
      return true if cached?(username, password)

      hash = users[username.to_s]
      if hash.nil?
        dummy_hash.is_password?(password.to_s)
        return false
      end
      return false unless hash.is_password?(password.to_s)

      remember(username, password)
      true
    end

    def cached?(username, password)
      users # Reloads the file, and clears the cache, when it changed.
      expires_at = @mutex.synchronize { @verified[cache_digest(username, password)] }
      !expires_at.nil? && expires_at > now
    end

    def remember(username, password)
      @mutex.synchronize do
        @verified.clear if @verified.size >= CACHE_MAX
        @verified[cache_digest(username, password)] = now + CACHE_TTL
      end
    end

    def cache_digest(username, password)
      OpenSSL::HMAC.digest("SHA256", @cache_key, "#{username}\0#{password}")
    end

    def now
      Process.clock_gettime(Process::CLOCK_MONOTONIC)
    end

    # Compared against when the user is unknown. It uses the highest cost in
    # the file, capped at MAX_DUMMY_COST, so a miss takes as long as a wrong
    # password. The hash is built outside the mutex so it blocks no one.
    def dummy_hash
      cost = dummy_cost(users.values.map(&:cost))
      @mutex.synchronize { @dummy_hashes[cost] } ||
        BCrypt::Password.create("geminabox-dummy", cost: cost).tap do |hash|
          @mutex.synchronize { @dummy_hashes[cost] ||= hash }
        end
    end

    def dummy_cost(costs)
      [costs.max || BCrypt::Engine::DEFAULT_COST, MAX_DUMMY_COST].min
    end

    def users
      path = file
      mtime = File.exist?(path) ? File.mtime(path) : nil
      @mutex.synchronize do
        unless @cache[:path] == path && @cache[:mtime] == mtime
          @cache = { path: path, mtime: mtime, users: mtime ? parse(File.read(path), path) : {} }
          @verified.clear
        end
        @cache[:users]
      end
    end

    def parse(content, path = file)
      content.each_line.with_index(1).with_object({}) do |(line, number), users|
        line = line.strip
        next if line.empty? || line.start_with?("#")

        name, hash = line.split(":", 2)
        if name.to_s.empty? || hash.nil?
          warn "[geminabox] #{path} line #{number} ignored: expected user:hash."
        elsif !hash.match?(BCRYPT_PREFIX)
          warn "[geminabox] #{path} line #{number} ignored (user #{name.inspect}): not a bcrypt hash. " \
               "Recreate it with: htpasswd -B #{path} #{name}"
        else
          users[name] = BCrypt::Password.new(hash)
        end
      rescue BCrypt::Errors::InvalidHash
        warn "[geminabox] #{path} line #{number} ignored (user #{name.inspect}): invalid bcrypt hash. " \
             "Recreate it with: htpasswd -B #{path} #{name}"
      end
    end

    def file
      ENV.fetch("GEMINABOX_HTPASSWD", nil).to_s.then do |path|
        path.empty? ? File.join(Geminabox.data, 'config', 'htpasswd') : path
      end
    end
  end
end
