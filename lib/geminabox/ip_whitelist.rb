# frozen_string_literal: true

require 'ipaddr'
require 'yaml'
require 'fileutils'

module Geminabox
  # IPs and CIDR ranges that skip login. Entries come from
  # GEMINABOX_IP_WHITELIST (comma-separated) and from
  # <Geminabox.data>/config/ip_whitelist.yml, which the admin page edits.
  module IpWhitelist
    module_function

    def matches?(list, ip)
      return false if ip.nil? || ip.empty?

      list.any? do |entry|
        entry.include?("/") ? IPAddr.new(entry).include?(ip) : entry == ip
      rescue IPAddr::Error
        false
      end
    end

    # The peer address. X-Forwarded-For counts only when the peer is listed
    # in GEMINABOX_TRUSTED_PROXIES. Rack's request.ip trusts any private
    # peer. Behind Docker's port mapping, any client can spoof it.
    def client_ip(env)
      remote = env["REMOTE_ADDR"].to_s.strip
      proxies = list_from_env("GEMINABOX_TRUSTED_PROXIES")
      return remote unless matches?(proxies, remote)

      forwarded = env["HTTP_X_FORWARDED_FOR"].to_s.split(",").map(&:strip).reject(&:empty?)
      forwarded.reverse.find { |ip| !matches?(proxies, ip) } || forwarded.first || remote
    end

    def include?(ip)
      matches?(entries, ip)
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
      IPAddr.new(entry)
      true
    rescue IPAddr::Error
      false
    end

    def normalize(entries)
      entries.map { |e| e.to_s.strip }.reject(&:empty?).uniq.sort
    end

    def file
      File.join(Geminabox.data, 'config', 'ip_whitelist.yml')
    end
  end
end
