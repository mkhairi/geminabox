# frozen_string_literal: true

require 'ipaddr'

module Geminabox
  # Blocks a client IP after repeated failed logins. The gate's Basic auth,
  # the /login form, and config.ru's push routes share one count per IP.
  #
  # GEMINABOX_AUTH_MAX_FAILURES failures (default 10) within
  # GEMINABOX_AUTH_BLOCK_SECONDS (default 300) block the IP for that many
  # seconds from the moment it reached the limit.
  #
  # A successful login never clears failures. Otherwise a valid htpasswd
  # login, which anyone with install access has, can reset failed admin
  # guesses and remove the limit. Failures expire when the window ends.
  #
  # IPv6 clients count per /64 network, because one host can use any
  # address in its /64.
  #
  # Counts live in this process only. Each worker process counts on its
  # own, and a restart clears every block.
  module LoginThrottle
    DEFAULT_MAX_FAILURES = 10
    DEFAULT_BLOCK_SECONDS = 300
    # Past this many entries, expired ones go first, then unblocked ones
    # with the fewest failures. Blocked entries go last, so a flood of new
    # IPs cannot lift an existing block or reset a partial count.
    MAX_TRACKED = 10_000

    @mutex = Mutex.new
    @entries = {}

    module_function

    # Seconds until the IP may try again, or nil when it is not blocked.
    def retry_after(ip)
      key = key_for(ip)
      @mutex.synchronize do
        entry = @entries[key]
        next nil unless entry&.dig(:blocked_until)

        remaining = entry[:blocked_until] - now
        if remaining <= 0
          @entries.delete(key)
          next nil
        end
        remaining.ceil
      end
    end

    def record_failure(ip)
      key = key_for(ip)
      @mutex.synchronize do
        entry = @entries[key]
        if entry.nil? || expired?(entry)
          @entries.delete(key)
          make_room
          entry = @entries[key] = { count: 0, first_at: now }
        end
        entry[:count] += 1
        next if entry[:blocked_until] || entry[:count] < max_failures

        entry[:blocked_until] = now + block_seconds
        warn "[geminabox] ip=#{ip} blocked for #{block_seconds}s after #{entry[:count]} failed logins."
      end
    end

    def reset!
      @mutex.synchronize { @entries.clear }
    end

    def size
      @mutex.synchronize { @entries.size }
    end

    def max_tracked
      MAX_TRACKED
    end

    # The count key: the IP itself, or its /64 network for IPv6.
    def key_for(ip)
      addr = IPAddr.new(ip.to_s)
      addr = addr.native
      addr.ipv6? ? "#{addr.mask(64)}/64" : addr.to_s
    rescue IPAddr::Error
      ip.to_s
    end

    def max_failures
      positive_env("GEMINABOX_AUTH_MAX_FAILURES", DEFAULT_MAX_FAILURES)
    end

    def block_seconds
      positive_env("GEMINABOX_AUTH_BLOCK_SECONDS", DEFAULT_BLOCK_SECONDS)
    end

    def now
      Process.clock_gettime(Process::CLOCK_MONOTONIC)
    end

    # A Rack response for a blocked IP.
    def too_many_response(ip, seconds)
      [
        429,
        { "content-type" => "text/plain", "retry-after" => seconds.to_s },
        ["Too many failed logins from #{ip}. Try again in #{seconds} seconds.\n"]
      ]
    end

    def expired?(entry)
      if entry[:blocked_until]
        entry[:blocked_until] <= now
      else
        now - entry[:first_at] >= block_seconds
      end
    end

    # Called with the mutex held, before a new entry is added.
    def make_room
      return if @entries.size < max_tracked

      @entries.delete_if { |_, entry| expired?(entry) }
      return if @entries.size < max_tracked

      # Free a tenth at once, so a flood of new IPs sorts rarely.
      excess = [@entries.size - max_tracked + 1, max_tracked / 10].max

      # Fewest failures go first, so a flood of one-off failures evicts
      # itself and not an attacker's partial count.
      victims = @entries.sort_by do |_, e|
        e[:blocked_until] ? [1, 0, e[:blocked_until]] : [0, e[:count], e[:first_at]]
      end
      victims.first(excess).each { |key, _| @entries.delete(key) }
    end

    def positive_env(name, default)
      value = Integer(ENV.fetch(name, ""), exception: false)
      value&.positive? ? value : default
    end
  end
end
