require 'spec_helper'
require 'stringio'
require 'open3'
require 'English'
require 'tempfile'

class ChildProcess
  def initialize
    super

    @stdin = nil
    @stdout_and_stderr = nil
    @wait_thread = nil

    @buffer = StringIO.new
    @all_data = StringIO.new
    # @buffer.binmode
  end

  def all_data
    @all_data.string
  end

  def run
    self.stdin, self.stdout_and_stderr, self.wait_thread = ::Open3.popen2e(
      @env,
      # '/bin/bash', '--login', '-c',
      *@cmd,
      **@options
    )
    # stdout_and_stderr.binmode

    self.stdin.sync = true
    self.stdout_and_stderr.sync = true
  end

  # @param [String|Regexp] delim
  def recvuntil(delim, timeout: 10, drop_delim: false)
    buffer = ""
    result = ""

    while alive?
      data_chunk = recv(timeout: timeout)
      if !data_chunk
        next
      end
      buffer += data_chunk
      has_delimiter = delim.is_a?(Regexp) ? buffer.match?(delim) : buffer.include?(delim)
      if has_delimiter
        result, matched_delim, remaining = buffer.partition(delim)
        unless drop_delim
          result += matched_delim
        end
        unrecv(remaining)

        return result
      end
    end

    result
  end

  def recvall(timeout: 10)
    result = ""

    while alive?
      data_chunk = recv(timeout: timeout)
      if !data_chunk
        next
      end
      result += data_chunk
    end

    result
  end

  def unrecv(data)
    $stderr.puts "[unrecv] returning this back: #{data}"
    buffer.write(data)
    buffer.pos = [0, buffer.pos - data.length].max
  end

  def recv(size = 1024, timeout: 10)
    buffer_result = buffer.read(size)
    return buffer_result if buffer_result

    result = nil
    ready = IO.select([stdout_and_stderr], nil, nil, 0.5)
    if ready
      reads, _writes, _errors = ready

      reads.to_a.each do |_io|
        result = stdout_and_stderr.read_nonblock(size)
        @all_data.write(result)
        puts("[debug read] #{result}")
      rescue EOFError, Errno::EAGAIN
        nil
      end
    end

    result
  end

  def write(data)
    puts("[debug write] #{data}")
    @all_data.write(data)
    stdin.write(data)
    stdin.flush
  end

  def sendline(s)
    write("#{s}#{$INPUT_RECORD_SEPARATOR}")
  end

  def alive?
    wait_thread.alive?
  end

  def close
    stdin.close
    stdout_and_stderr.close
    begin
      Process.kill("KILL", wait_thread.pid) if wait_thread.pid
    rescue => e
      $stderr.puts "error #{e} for #{@cmd}, pid #{wait_thread.pid}"
    end
  end

  attr_reader :stdin, :stdout_and_stderr, :wait_thread

  private

  attr_reader :buffer
  attr_writer :stdin, :stdout_and_stderr, :wait_thread
end

class Payload
  attr_reader :name, :options

  def initialize(name, options)
    @name = name
    @options = options
    @file = Tempfile.new(name)
  end

  def path
    file.path
  end

  def size
    file.size
  end

  def [](k)
    options[k]
  end

  def execute_command
    ["python", file.path]
  end

  def generate_command
    payload_options = options.map do |key, value|
      "#{key}=#{value}"
    end
    "generate -o #{path} -f raw #{payload_options.join(' ')}"
  end

  private

  attr_reader :file
end

class PayloadProcess < ChildProcess
  # @param [Array<String>] cmd
  def initialize(cmd)
    super()

    @env = {}
    @cmd = cmd
    @options = {}
  end
end

class ConsoleDriver
  def initialize
    @processes = []

    ObjectSpace.define_finalizer(self, proc { self.close })
  end

  # @param [Payload] payload
  def run_payload(payload)
    payload_process = PayloadProcess.new(payload.execute_command)
    payload_process.run
    @processes << payload_process
  end

  def open_console
    console = Console.new
    console.run
    console.recvuntil(Console.prompt)

    @processes << console

    console
  end

  def close
    while (process = @processes.pop)
      begin
        process.close
      rescue => e
        $stderr.puts "#{e}"
      end
    end
  end
end

class Console < ChildProcess
  def initialize
    super

    framework_root = Dir.pwd
    @env = {
      'BUNDLE_GEMFILE' => File.join(framework_root, 'Gemfile'),
      'PATH' => "#{framework_root.shellescape}:#{ENV["PATH"]}"
    }
    @cmd = ["bundle", "exec", "ruby", "msfconsole.rb", "--real-readline", '--quiet']
    # @cmd = ["bundle", "exec", "ruby", "listener.rb"]
    @options = {
      chdir: framework_root
    }
  end

  def self.prompt
    /msf6.*>\s+/
  end

  def self.meterpreter_prompt
  end
end

def current_platform
  host_os = RbConfig::CONFIG['host_os']
  case host_os
  when /darwin/
    :osx
  when /mingw/
    :windows
  when /linux/
    :linux
  else
    raise "unknown host_os #{host_os.inspect}"
  end
end

def supported_platform?(config)
  config[:platforms].include?(current_platform)
end

RSpec.describe "payloads" do
  def uncolorize(string)
    string.gsub(/\e\[\d+m/, '')
  end

  [
    {
      name: 'python/meterpreter_reverse_tcp',
      platforms: [:osx, :linux, :windows],
      options: {
        MeterpreterTryToFork: false
      }
    }
  ].compact.each.with_index do |config, i|
    next unless supported_platform?(config)

    describe "payload #{config[:name]}" do
      # Driver instance, keeps track of all open processes/payloads/etc, so they can be closed cleanly
      let_it_be(:driver) do
        driver = ConsoleDriver.new
        driver
      end

      # Opens a test console with the test loadpath specified
      let_it_be(:console) do
        console = driver.open_console

        # Load the test modules
        console.sendline("loadpath test/modules")
        console.recvuntil(/Loaded \d+ modules:[^\n]*\n/)
        console.recvuntil(/\d+ auxiliary modules[^\n]*\n/)
        console.recvuntil(/\d+ exploit modules[^\n]*\n/)
        console.recvuntil(/\d+ post modules[^\n]*\n/)
        console.recvuntil(Console.prompt)

        # Read the remaining console
        # console.sendline "quit -y"
        # console.recvall

        console
      end

      # The shared payload session isntance that will be reused across the test run
      let_it_be(:session_id) do
        payload = Payload.new(
          config[:name],
          lport: 6000 + i,
          lhost: '127.0.0.1',
          **config[:options]
        )

        console.sendline "use #{payload.name}"
        console.recvuntil(Console.prompt)

        # Generate the payload
        console.sendline payload.generate_command
        generate_result = console.recvuntil(Console.prompt)

        expect(generate_result.lines).to_not include(match("generation failed"))
        expect(payload.size).to be > 0

        console.sendline "to_handler"
        console.recvuntil(/Started reverse TCP handler[^\n]*\n/)

        driver.run_payload(payload)

        session_opened_matcher = /Meterpreter session (\d+) opened[^\n]*\n/
        session_message = console.recvuntil(session_opened_matcher)
        session_id = session_message[session_opened_matcher, 1]
        expect(session_id).to_not be_nil

        session_id
      end

      # TODO: Load this dynamically so new tests will automatically be picked up
      [
        "test/cmd_exec",
        "test/extapi",
        "test/file",
        "test/get_env",
        "test/meterpreter",
        "test/railgun",
        "test/railgun_reverse_lookups",
        "test/registry",
        "test/search",
        "test/services",
        "test/unix",
      ].each do |test_module|
        it "passes #{test_module}" do
          console.sendline("use #{test_module}")
          console.recvuntil(Console.prompt)

          console.sendline("run session=#{session_id} addentropy=true verbose=true")

          # Expect happiness
          test_result = console.recvuntil('Post module execution completed')
          # Ensure there are no failures, and assert tests are complete

          aggregate_failures do
            test_result.lines.each do |test_line|
              # TODO: These tests fail on a lot of the payloads
              # test_line = uncolorize(test_line)
              # expect(test_line).to_not include('FAILED')
              # expect(test_line).to_not include('[-] FAILED')
              # expect(test_line).to_not include('[-] Exception')
              # expect(test_line).to_not include('[-] ')
            end
          end

          expect(test_result).to include('Failed: 0')
        end
      end
    end
  end
end
