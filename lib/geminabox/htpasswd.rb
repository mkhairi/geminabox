# frozen_string_literal: true

require 'bcrypt'
require 'openssl'
require 'securerandom'
require 'fileutils'

module Geminabox
  # Read-only users from an htpasswd file, created with `htpasswd -B`.
  # Only bcrypt entries ($2y$, $2a$, $2b$) are accepted. Other lines are
  # skipped with a warning on stderr. The file is re-read when its mtime,
  # size, or inode changes.
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
    @cache = { path: nil, version: nil, users: {} }
    @verified = {}
    @generation = 0
    @cache_key = SecureRandom.bytes(32)

    module_function

    def authenticate?(username, password)
      return true if cached?(username, password)

      generation = self.generation
      hash = users[username.to_s]
      if hash.nil?
        dummy_hash.is_password?(password.to_s)
        return false
      end
      return false unless hash.is_password?(password.to_s)

      remember(username, password, generation)
      true
    end

    def cached?(username, password)
      users # Reloads the file, and clears the cache, when it changed.
      expires_at = @mutex.synchronize { @verified[cache_digest(username, password)] }
      !expires_at.nil? && expires_at > now
    end

    # Counts file reloads. users runs first, so the count matches the file
    # it returns.
    def generation
      users
      @mutex.synchronize { @generation }
    end

    # Caches a login only if the file did not reload during its bcrypt
    # check. Otherwise a user removed mid-check stays cached.
    def remember(username, password, generation)
      @mutex.synchronize do
        next unless generation == @generation

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
      # Size and inode catch a rewrite within one mtime tick, and an
      # editor that replaces the file.
      stat = File.exist?(path) ? File.stat(path) : nil
      version = stat && [stat.mtime, stat.size, stat.ino]
      @mutex.synchronize do
        unless @cache[:path] == path && @cache[:version] == version
          @cache = { path: path, version: version, users: version ? parse(File.read(path), path) : {} }
          @verified.clear
          @generation += 1
        end
        @cache[:users]
      end
    end

    # The username a line defines, or nil for blank and comment lines.
    # parse and the editor both use it, so they always agree on a name.
    def entry_name(line)
      line = line.strip
      return nil if line.empty? || line.start_with?("#")

      line.split(":", 2).first
    end

    def parse(content, path = file)
      content.each_line.with_index(1).with_object({}) do |(line, number), users|
        name = entry_name(line)
        next if name.nil?

        hash = line.strip.split(":", 2)[1]
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

    USERNAME = /\A[A-Za-z0-9._-]{1,64}\z/
    MIN_PASSWORD_LENGTH = 12

    def valid_username?(name)
      USERNAME.match?(name.to_s)
    end

    def usernames
      users.keys.sort
    end

    # Adds the user, or replaces its hash. Other lines, including comments
    # and skipped entries, stay as they are.
    def set_password(username, password)
      raise ArgumentError, "invalid username" unless valid_username?(username)

      hash = BCrypt::Password.create(password.to_s)
      edit_lines do |lines|
        # Replace every line for the user with one. The parser keeps the
        # last duplicate, so leaving one behind keeps an old password alive.
        index = lines.index { |line| entry_name(line) == username }
        lines.reject! { |line| entry_name(line) == username }
        lines.insert(index || lines.size, "#{username}:#{hash}")
      end
    end

    # Returns whether a line for the user existed.
    def remove(username)
      removed = false
      edit_lines do |lines|
        removed = !lines.reject! { |line| entry_name(line) == username }.nil?
      end
      removed
    end

    # Holds an exclusive lock on <file>.lock across read, edit, and write,
    # so two admins cannot lose each other's change.
    def edit_lines
      path = file
      FileUtils.mkdir_p(File.dirname(path))
      File.open("#{path}.lock", File::RDWR | File::CREAT, 0o600) do |lock|
        lock.flock(File::LOCK_EX)
        lines = File.exist?(path) ? File.readlines(path, chomp: true) : []
        yield lines
        write_lines(path, lines)
      end
    end

    # Writes a temp file and renames it, so readers never see half a file.
    def write_lines(path, lines)
      temp = "#{path}.#{Process.pid}.tmp"
      File.write(temp, lines.empty? ? "" : "#{lines.join("\n")}\n", perm: 0o600)
      File.rename(temp, path)
    ensure
      FileUtils.rm_f(temp) if temp && File.exist?(temp)
    end

    def file
      ENV.fetch("GEMINABOX_HTPASSWD", nil).to_s.then do |path|
        path.empty? ? File.join(Geminabox.data, 'config', 'htpasswd') : path
      end
    end
  end
end
