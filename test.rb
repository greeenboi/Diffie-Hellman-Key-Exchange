require 'json'
require 'net/http'
require 'uri'
require 'webrick'
require 'digest'
require_relative './algo'

# ---------------------------
# Server side (PartyB)
# ---------------------------
# Support threaded start for one-shot client+server run
# start_in_thread: when true, starts WEBrick in a background thread and returns [server, thread]
# otherwise blocks until shutdown as before.
def start_server(port, start_in_thread: false)
  # Small demo params; fine for testing, not for production use.
  modulus = 23
  base = 5

  party = PartyB.new(name: "Server", modulus: modulus, base: base)
  party.pick_secret
  party.derive_public_key

  server_shared_secret = nil

  server = WEBrick::HTTPServer.new(
    Port: port,
    BindAddress: '127.0.0.1',
    AccessLog: [],
    Logger: WEBrick::Log.new($stderr, WEBrick::Log::WARN)
  )

  server.mount_proc('/params') do |req, res|
    res['Content-Type'] = 'application/json'
    res.body = { modulus: modulus, base: base }.to_json
  end

  server.mount_proc('/client-public') do |req, res|
    unless req.request_method == 'POST'
      res.status = 405
      res.body = { error: 'POST required' }.to_json
      next
    end
    begin
      payload = JSON.parse(req.body || '{}')
      client_public = Integer(payload['public'])
      server_shared_secret = party.compute_shared_secret(client_public)
      res['Content-Type'] = 'application/json'
      res.body = { public: party.public_key }.to_json
    rescue => e
      res.status = 400
      res.body = { error: e.message }.to_json
    end
  end

  server.mount_proc('/verify') do |req, res|
    unless req.request_method == 'POST'
      res.status = 405
      res.body = { error: 'POST required' }.to_json
      next
    end
    if server_shared_secret.nil?
      res.status = 409
      res.body = { error: 'shared secret not established yet' }.to_json
      next
    end
    payload = JSON.parse(req.body || '{}')
    client_hash = payload['hash'].to_s
    server_hash = Digest::SHA256.hexdigest(server_shared_secret.to_s)
    res['Content-Type'] = 'application/json'
    res.body = { match: (client_hash == server_hash) }.to_json
  end

  trap('INT') { server.shutdown }
  puts "Server running on http://127.0.0.1:#{port}"
  puts "Params: p=#{modulus}, g=#{base}, server_public=#{party.public_key}"

  if start_in_thread
    t = Thread.new { server.start }
    t.abort_on_exception = true
    return [server, t]
  else
    server.start
  end
end

# ---------------------------
# Client side (PartyA)
# ---------------------------
def join_url(base_url, path)
  base_url.chomp('/') + path
end

# Simple readiness probe for the server
def wait_for_server(base_url, timeout_seconds: 5)
  deadline = Time.now + timeout_seconds
  last_error = nil
  until Time.now > deadline
    begin
      uri = URI(join_url(base_url, '/params'))
      res = Net::HTTP.get_response(uri)
      return true if res.is_a?(Net::HTTPSuccess)
    rescue => e
      last_error = e
    end
    sleep 0.1
  end
  raise("Server not ready at #{base_url} within #{timeout_seconds}s#{last_error ? ": #{last_error.message}" : ''}")
end

def http_get_json(url)
  uri = URI(url)
  res = Net::HTTP.get_response(uri)
  raise "GET #{uri} failed: #{res.code}" unless res.is_a?(Net::HTTPSuccess)
  JSON.parse(res.body)
end

def http_post_json(url, payload)
  uri = URI(url)
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = (uri.scheme == 'https')
  req = Net::HTTP::Post.new(uri.request_uri, 'Content-Type' => 'application/json')
  req.body = payload.to_json
  res = http.request(req)
  raise "POST #{uri} failed: #{res.code} #{res.body}" unless res.is_a?(Net::HTTPSuccess)
  JSON.parse(res.body)
end

def run_client(base_url)
  # 1) Fetch params
  params = http_get_json(join_url(base_url, '/params'))
  p = Integer(params['modulus'])
  g = Integer(params['base'])

  # 2) Create client party and compute public
  client = PartyA.new(name: "Client", modulus: p, base: g)
  client.pick_secret
  client.derive_public_key

  # 3) Send client public, receive server public
  resp = http_post_json(join_url(base_url, '/client-public'), { public: client.public_key })
  server_public = Integer(resp['public'])

  # 4) Compute shared and verify via hash
  shared = client.compute_shared_secret(server_public)
  digest = Digest::SHA256.hexdigest(shared.to_s)
  verify = http_post_json(join_url(base_url, '/verify'), { hash: digest })

  puts "Client results:"
  puts "  p=#{p}, g=#{g}"
  puts "  client_public=#{client.public_key}"
  puts "  server_public=#{server_public}"
  puts "  shared_secret=#{shared}"
  puts "  hash_match=#{verify['match']}"
end

# Convenience: run server and client in one process
def run_both(port: 9292)
  base_url = "http://127.0.0.1:#{port}"
  server, thread = start_server(port, start_in_thread: true)
  begin
    wait_for_server(base_url)
    run_client(base_url)
  ensure
    server.shutdown
    thread.join
  end
end

# ---------------------------
# CLI
# ---------------------------
if __FILE__ == $0
  mode = ARGV[0]
  case mode
  when nil, 'both'
    # Default: run server and client automatically
    port = (ARGV[1] || '9292').to_i
    run_both(port: port)
  when 'server'
    port = (ARGV[1] || '9292').to_i
    start_server(port)
  when 'client'
    base_url = ARGV[1] || 'http://127.0.0.1:9292'
    run_client(base_url)
  else
    puts "Usage:"
    puts "  ruby test.rb                # run server+client"
    puts "  ruby test.rb both [port]    # same as default"
    puts "  ruby test.rb server [port]"
    puts "  ruby test.rb client [base_url]"
    exit 1
  end
end
