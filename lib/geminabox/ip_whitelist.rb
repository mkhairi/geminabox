# frozen_string_literal: true

require 'ipaddr'
require 'socket'
require 'yaml'
require 'fileutils'

module Geminabox
  # IPs and CIDR ranges that skip login. Entries come from
  # GEMINABOX_IP_WHITELIST (comma-separated) and from
  # <Geminabox.data>/config/ip_whitelist.yml, which the admin page edits.
  module IpWhitelist
    module_function

    # Ranges broader than these are treated as typos and never match, so
    # an entry such as 1.2.3.4/0 cannot open the gate to everyone.
    MIN_PREFIX = { Socket::AF_INET => 8, Socket::AF_INET6 => 32 }.freeze

    def matches?(list, ip)
      return false if ip.nil? || ip.empty?

      list.any? do |entry|
        range = parse(entry)
        range ? range.include?(ip) : false
      rescue IPAddr::Error
        false
      end
    end

    # The entry as an IPAddr, or nil when it is invalid or too broad.
    def parse(entry)
      range = IPAddr.new(entry)
      range.prefix >= MIN_PREFIX.fetch(range.family) ? range : nil
    rescue IPAddr::Error
      nil
    end

    # The peer address. X-Forwarded-For counts only when the peer is listed
    # in GEMINABOX_TRUSTED_PROXIES. Rack's request.ip trusts any private
    # peer. Behind Docker's port mapping, any client can spoof it.
    def client_ip(env)
      remote = env["REMOTE_ADDR"].to_s.strip
      proxies = list_from_env("GEMINABOX_TRUSTED_PROXIES")
      return remote unless matches?(proxies, remote)

      forwarded = env["HTTP_X_FORWARDED_FOR"].to_s.split(",").map(&:strip).reject(&:empty?)
      forwarded.reverse.find { |ip| !matches?(proxies, ip) } || remote
    end

    def include?(ip)
      matches?(entries, ip)
    end

    FORWARDING_HEADERS = %w[HTTP_X_FORWARDED_FOR HTTP_FORWARDED HTTP_X_REAL_IP].freeze
    # Peers already warned about, so a misconfigured proxy logs once.
    @warned_peers = {}
    @warned_mutex = Mutex.new

    # Whether the request may skip login by IP. A forwarding header from a
    # peer not in GEMINABOX_TRUSTED_PROXIES means the real client is
    # unknown. The whitelist is then ignored, so a proxy without that
    # setting makes everyone log in instead of letting everyone in.
    def whitelisted?(env)
      remote = env["REMOTE_ADDR"].to_s.strip
      if FORWARDING_HEADERS.any? { |h| !env[h].to_s.strip.empty? } &&
         !matches?(list_from_env("GEMINABOX_TRUSTED_PROXIES"), remote)
        warn_untrusted_proxy(remote)
        return false
      end

      include?(client_ip(env))
    end

    def reset_warnings!
      @warned_mutex.synchronize { @warned_peers.clear }
    end

    def warn_untrusted_proxy(remote)
      first = @warned_mutex.synchronize do
        next false if @warned_peers.key?(remote)

        @warned_peers.clear if @warned_peers.size >= 1000
        @warned_peers[remote] = true
      end
      return unless first

      warn "[geminabox] IP whitelist ignored: request from #{remote} carries a forwarding header, " \
           "but GEMINABOX_TRUSTED_PROXIES does not list #{remote}. If it is your proxy, " \
           "set GEMINABOX_TRUSTED_PROXIES=#{remote}."
    end

    def entries
      normalize(persistent_entries + env_entries)
    end

    def env_entries
      list_from_env("GEMINABOX_IP_WHITELIST")
    end

    def list_from_env(name)
      value = ENV.fetch(name, nil)
      return [] if value.nil? || value.strip.empty?

      normalize(value.split(/\s*,\s*/))
    end

    def persistent_entries
      return [] unless File.exist?(file)

      normalize(Array(YAML.load_file(file)).map(&:to_s))
    rescue Psych::SyntaxError
      []
    end

    def save(entries)
      FileUtils.mkdir_p(File.dirname(file))
      File.write(file, normalize(entries).to_yaml)
    end

    def valid_entry?(entry)
      !parse(entry).nil?
    end

    def normalize(entries)
      entries.map { |e| e.to_s.strip }.reject(&:empty?).uniq.sort
    end

    def file
      File.join(Geminabox.data, 'config', 'ip_whitelist.yml')
    end
  end
end
