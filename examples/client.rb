#!/usr/bin/env ruby
# frozen_string_literal: true
#
# Fetch a secret from a running rosa agent.
# Require this file and call rosa_get, or run: client.rb NAME

require 'json'
require 'socket'

def rosa_get(name)
  sock = ENV['ROSA_SOCK'] ||
         File.join(ENV.fetch('XDG_RUNTIME_DIR', "/run/user/#{Process.uid}"), 'rosa.sock')
  UNIXSocket.open(sock) do |s|
    s.puts JSON.generate(op: 'get', name: name)
    # A confirm-gated secret blocks here until the human decides.
    reply = JSON.parse(s.gets)
    raise "rosa: #{reply['error'] || 'unknown error'}" unless reply['ok']

    reply['value']
  end
end

print rosa_get(ARGV.fetch(0)) if __FILE__ == $PROGRAM_NAME
