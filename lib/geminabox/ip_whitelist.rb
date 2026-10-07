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

    def include?(ip)
      return false if ip.nil? || ip.empty?

      entries.any? do |entry|
        entry.include?("/") ? IPAddr.new(entry).include?(ip) : entry == ip
      rescue IPAddr::Error
        false
      end
    end

    def entries
      normalize(persistent_entries + env_entries)
    end

    def env_entries
      value = ENV.fetch("GEMINABOX_IP_WHITELIST", nil)
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
