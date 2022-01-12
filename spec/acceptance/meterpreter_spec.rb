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

    puts wait_thread.alive?
  end

  # @param [String|Regexp] delim
  def recvuntil(delim, timeout: 10, drop_delim: false)
    buffer = ""
    result = ""

    while alive?
      ready = IO.select([stdout_and_stderr], nil, nil, 0.5)

      puts "still no luck searching for #{delim} in #{buffer}"

      if ready
        reads, _writes, _errors = ready

        reads.to_a.each do |_io|
          buffer += recv(timeout: timeout)
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
      end
    end

    result
  end

  def recvall(timeout: 10)
    result = ""

    while alive?
      ready = IO.select([stdout_and_stderr], nil, nil, 0.1)

      if ready
        reads, _writes, _errors = ready

        reads.to_a.each do |_io|
          result += recv(timeout: timeout)
        end
      end
    end

    result
  end

  def unrecv(data)
    $stderr.puts "[unrecv] returning this back: #{data}"
    buffer.ungetc(data)
  end

  def recv(size = 1024, timeout: 10)
    buffer_result = buffer.read(size)
    return buffer_result if buffer_result

    data = stdout_and_stderr.read_nonblock(size)
    @all_data.write(data)
    puts("[debug read] #{data}")
    data
  rescue EOFError, Errno::EAGAIN
    ''
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

RSpec.describe "payloads" do
  def uncolorize(string)
    string.gsub(/\e\[\d+m/, '')
  end

  describe "python meterpreter" do
    it "opens sessions" do
      driver = ConsoleDriver.new
      console = driver.open_console

      payload = Payload.new(
        'python/meterpreter_reverse_tcp',
        lport: 6000,
        lhost: '127.0.0.1',
        MeterpreterTryToFork: false
      )

      console.sendline "use #{payload.name}"
      usage_data = console.recvuntil(Console.prompt)

      # Generate the payload
      console.sendline payload.generate_command
      generate_result = console.recvuntil(Console.prompt)

      puts "buffer data:"
      puts "--------------------------"
      puts console.all_data.to_s
      puts "--------------------------"

      expect(generate_result.lines).to_not include(match("generation failed"))
      expect(payload.size).to be > 0

      console.sendline "to_handler"
      console.recvuntil("Started reverse TCP handler")

      driver.run_payload(payload)

      session_opened_matcher = /Meterpreter session (\d+) opened/
      session_message = console.recvuntil(session_opened_matcher)
      session_id = session_message[session_opened_matcher, 1]
      expect(session_id).to_not be_nil

      # Load the test modules
      console.sendline("loadpath test/modules")
      console.recvuntil(/Loaded \d+ modules:/)
      console.recvuntil(Console.prompt)

      # Run a test module
      console.sendline("use test/meterpreter")
      console.recvuntil(Console.prompt)

      console.sendline("run session=#{session_id}")

      # Expect happiness
      test_result = console.recvuntil('Post module execution completed')
      # Ensure there are no failures, and assert tests are complete
      aggregate_failures do
        test_result.lines.each do |test_line|
          test_line = uncolorize(test_line)

          # expect(test_line).to_not include('FAILED')
          # expect(test_line).to_not include('[-] FAILED')
          # expect(test_line).to_not include('[-] Exception')
          # expect(test_line).to_not include('[-] ')
        end
      end

      expect(test_result).to include('Failed: 0')

      # Read the remaining console
      console.sendline "quit -y"
      console.recvall

      console.close

      expect(true).to be true
    end
  end
end
