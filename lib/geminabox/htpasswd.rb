# frozen_string_literal: true

require 'bcrypt'

module Geminabox
  # Read-only users from an htpasswd file, created with `htpasswd -B`.
  # Only bcrypt entries ($2y$, $2a$, $2b$) are accepted. Other hash formats
  # are skipped. The file is re-read when its mtime changes.
  #
  # Path: GEMINABOX_HTPASSWD, or <Geminabox.data>/config/htpasswd.
  module Htpasswd
    BCRYPT_PREFIX = /\A\$2[aby]\$/

    @mutex = Mutex.new
    @dummy_hashes = {}
    @cache = { path: nil, mtime: nil, users: {} }

    module_function

    def authenticate?(username, password)
      hash = users[username.to_s]
      if hash.nil?
        dummy_hash.is_password?(password.to_s)
        return false
      end

      hash.is_password?(password.to_s)
    end

    # Compared against when the user is unknown. It uses the highest cost in
    # the file, so a miss takes as long as a wrong password.
    def dummy_hash
      cost = users.values.map(&:cost).max || BCrypt::Engine::DEFAULT_COST
      @mutex.synchronize do
        @dummy_hashes[cost] ||= BCrypt::Password.create("geminabox-dummy", cost: cost)
      end
    end

    def users
      path = file
      mtime = File.exist?(path) ? File.mtime(path) : nil
      @mutex.synchronize do
        unless @cache[:path] == path && @cache[:mtime] == mtime
          @cache = { path: path, mtime: mtime, users: mtime ? parse(File.read(path)) : {} }
        end
        @cache[:users]
      end
    end

    def parse(content)
      content.each_line.with_object({}) do |line, users|
        line = line.strip
        next if line.empty? || line.start_with?("#")

        name, hash = line.split(":", 2)
        next if name.to_s.empty? || !hash&.match?(BCRYPT_PREFIX)

        users[name] = BCrypt::Password.new(hash)
      rescue BCrypt::Errors::InvalidHash
        next
      end
    end

    def file
      ENV.fetch("GEMINABOX_HTPASSWD", nil).to_s.then do |path|
        path.empty? ? File.join(Geminabox.data, 'config', 'htpasswd') : path
      end
    end
  end
end
