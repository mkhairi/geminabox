# frozen_string_literal: true

module Geminabox
  # Blocks a client IP after repeated failed logins. The gate's Basic auth,
  # the /login form, and config.ru's push routes share one count per IP.
  #
  # GEMINABOX_AUTH_MAX_FAILURES failures (default 10) within
  # GEMINABOX_AUTH_BLOCK_SECONDS (default 300) block the IP for that many
  # seconds from the moment it reached the limit.
  #
  # Counts live in this process only. Each worker process counts on its
  # own, and a restart clears every block.
  module LoginThrottle
    DEFAULT_MAX_FAILURES = 10
    DEFAULT_BLOCK_SECONDS = 300
    # Past this many IPs, expired entries are pruned. If every entry is
    # still live, all counts reset, so memory stays bounded.
    MAX_TRACKED = 10_000

    @mutex = Mutex.new
    @entries = {}

    module_function

    # Seconds until the IP may try again, or nil when it is not blocked.
    def retry_after(ip)
      @mutex.synchronize do
        entry = @entries[ip.to_s]
        next nil unless entry&.dig(:blocked_until)

        remaining = entry[:blocked_until] - now
        if remaining <= 0
          @entries.delete(ip.to_s)
          next nil
        end
        remaining.ceil
      end
    end

    def record_failure(ip)
      @mutex.synchronize do
        prune if @entries.size >= MAX_TRACKED
        entry = @entries[ip.to_s]
        entry = @entries[ip.to_s] = { count: 0, first_at: now } if entry.nil? || expired?(entry)
        entry[:count] += 1
        next if entry[:blocked_until] || entry[:count] < max_failures

        entry[:blocked_until] = now + block_seconds
        warn "[geminabox] ip=#{ip} blocked for #{block_seconds}s after #{entry[:count]} failed logins."
      end
    end

    def reset(ip)
      @mutex.synchronize { @entries.delete(ip.to_s) }
    end

    def reset!
      @mutex.synchronize { @entries.clear }
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

    def prune
      @entries.delete_if { |_, entry| expired?(entry) }
      @entries.clear if @entries.size >= MAX_TRACKED
    end

    def positive_env(name, default)
      value = Integer(ENV.fetch(name, ""), exception: false)
      value&.positive? ? value : default
    end
  end
end
