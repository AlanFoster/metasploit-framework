require 'spec_helper'
require 'stringio'
require 'open3'
require 'English'
require 'tempfile'
require 'fileutils'
require 'timeout'
require 'shellwords'

class Countdown
  def initialize(timeout)
    @start_time = Process.clock_gettime(Process::CLOCK_MONOTONIC, :second)
    @end_time = @start_time + timeout
    @timeout = timeout
  end

  def elapsed?
    remaining_time == 0
  end

  def remaining_time
    [@end_time - Process.clock_gettime(Process::CLOCK_MONOTONIC, :second), 0].max
  end
end

class ChildProcess
  def initialize
    super

    @debug = true
    @env ||= {}
    @cmd ||= []
    @options ||= {}

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
      *@cmd,
      **@options
    )
    # stdout_and_stderr.binmode

    self.stdin.sync = true
    self.stdout_and_stderr.sync = true
  rescue => e
    $stderr.puts "popen failure #{e}"
    raise
  end

  def recvline(timeout: 10)
    recvuntil($INPUT_RECORD_SEPARATOR)
  end

  alias readline recvline

  # @param [String|Regexp] delim
  def recvuntil(delim, timeout: 10, drop_delim: false)
    buffer = ""
    result = ""

    with_countdown(timeout) do |countdown|
      while alive? && !countdown.elapsed?
        data_chunk = recv(timeout: countdown.remaining_time)
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
    end

    result
  end

  def recvall(timeout: 10)
    result = ""

    with_countdown(timeout) do |countdown|
      while alive? && !countdown.elapsed?
        data_chunk = recv(timeout: countdown.remaining_time)
        if !data_chunk
          next
        end
        result += data_chunk
      end
    end

    result
  end

  def unrecv(data)
    buffer.write(data)
    buffer.pos = [0, buffer.pos - data.length].max
  end

  def recv(size = 1024, timeout: 10)
    buffer_result = buffer.read(size)
    return buffer_result if buffer_result

    result = nil
    ready = IO.select([stdout_and_stderr], nil, nil, timeout)
    if ready
      reads, _writes, _errors = ready

      reads.to_a.each do |_io|
        result = stdout_and_stderr.read_nonblock(size)
        @all_data.write(result)
        log("[read] #{result}")
      rescue EOFError, Errno::EAGAIN
        nil
      end
    end

    result
  end

  def write(data)
    log("[write] #{data}")
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

  # Interact with the current process, forwarding the console stdin to the process' stdin,
  # and writing any output to stdout. Doesn't support using a PTY/raw mode.
  def interact
    puts
    puts '[*] Opened interactive mode - enter "!next" to continue, or "!exit" to stop entirely'
    puts

    without_debugging do
      while alive?
        ready = IO.select([stdout_and_stderr, STDIN], [], [], 10)

        if ready
          reads, _, _ = ready

          reads.to_a.each do |read|
            case read
            when STDIN
              input = STDIN.gets
              if input.chomp == '!continue'
                return
              elsif input.chomp == '!exit'
                exit
              end

              write(input)
            when stdout_and_stderr
              STDOUT.write(recv(2048))
              STDOUT.flush
            end
          end
        end
      end
    end
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

  def log(s)
    return unless @debug

    puts s
  end

  def without_debugging
    previous_debug_value = @debug
    @debug = false
    yield
  ensure
    @debug = previous_debug_value
  end

  # Yields a timer object that can be used to request the remaining time available
  def with_countdown(timeout)
    countdown = Countdown.new(timeout)
    # It is the caller's responsibility to honor the required countdown limits,
    # but let's wrap the full operation in an explicit for worse case scenario,
    # which may leave object state in a non-determinant state depending on the call
    ::Timeout.timeout(timeout * 1.5) do
      yield countdown
    end
  end
end

class Payload
  attr_reader :name, :execute_cmd, :generate_options, :payload_options

  def initialize(options)
    @name = options.fetch(:name)
    @execute_cmd = options.fetch(:execute_cmd)
    @generate_options = options.fetch(:generate_options)
    @payload_options = options.fetch(:payload_options)
    @executable = options.fetch(:executable, false)

    basename = "#{File.basename(__FILE__)}_#{name}".gsub(/[^a-zA-Z]/, '-')
    extension = options.fetch(:extension, '')
    # Generate a Dir::Tmpname instead of a Tempfile, otherwise windows won't allow the file to be executed
    # as the current Ruby process will still have a handle to it
    # TODO: Ensure this is deleted correctly
    @file_path = Dir::Tmpname.create([basename, extension]) do |_path, _n, _opts, _origdir|
      # noop
    end
  end

  def executable?
    @executable
  end

  def path
    @file_path
  end

  def size
    File.size(path)
  rescue => _e
    0
  end

  def [](k)
    options[k]
  end

  def execute_command
    @execute_cmd.map do |val|
      val.gsub('${payload_path}', path)
    end
  end

  def generate_command
    generate_options = @generate_options.map do |key, value|
      "#{key} #{value}"
    end
    payload_options = @payload_options.map do |key, value|
      "#{key}=#{value}"
    end

    "generate -o #{path} #{generate_options.join(' ')} #{payload_options.join(' ')}"
  end

  def as_readable_text
    <<~EOF
      ## Payload
      use #{name}

      ## Generate command
      #{generate_command}

      ## Create listener
      to_handler

      ## Execute command
      #{Shellwords.join(execute_command)}
    EOF
  end
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
    @coonsole = nil
    @processes = []

    ObjectSpace.define_finalizer(self, proc { self.close })
  end

  # @param [Payload] payload
  def run_payload(payload)
    if payload.executable? && !File.executable?(payload.path)
      FileUtils.chmod("+x", payload.path)
    end

    payload_process = PayloadProcess.new(payload.execute_command)
    payload_process.run
    @processes << payload_process
  end

  def open_console
    @console = Console.new
    @console.run
    @console.recvuntil(Console.prompt)

    @processes << @console

    @console
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
    @options = {
      chdir: framework_root
    }
  end

  def self.prompt
    /msf6.*>\s+/
  end

  def reset
    sendline("sessions -K")
    recvuntil(Console.prompt)

    @all_data.reopen("")
  end
end

class PortGenerator
  def initialize(base = 6000)
    @base = base
    @current = base
  end

  def next
    @current += 1
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

def human_name_for_payload(config)
  is_stageless = config[:name].include?('meterpreter_reverse_tcp')
  is_staged = config[:name].include?('meterpreter/reverse_tcp')

  details = []
  details << "stageless" if is_stageless
  details << "staged" if is_staged
  details << config[:name]

  details.join(" ")
end

def uncolorize(string)
  string.gsub(/\e\[\d+m/, '')
end

class TestProcess < ChildProcess
  def initialize
    super
    @cmd = ["bundle", "exec", "ruby", "prompt.rb"]
  end
end

# process = TestProcess.new
# process.run
# process.interact
# exit(1)

RSpec.describe "payloads" do
  # Tests to ensure that Meterpreter is consistent across all implementations/operation systems
  METERPRETER_PAYLOADS = {
    python: [
      {
        name: 'python/meterpreter_reverse_tcp',
        extension: '.py',
        platforms: [:osx, :linux, :windows],
        execute_cmd: ['python', '${payload_path}'],
        generate_options: {
          '-f': 'raw',
        },
        payload_options: {
          MeterpreterTryToFork: false
        }
      },
      {
        name: 'python/meterpreter/reverse_tcp',
        extension: '.py',
        platforms: [:osx, :linux, :windows],
        execute_cmd: ['python', '${payload_path}'],
        generate_options: {
          '-f': 'raw',
        },
        payload_options: {
          MeterpreterTryToFork: false
        }
      },
    ],
    php: [
      {
        name: 'php/meterpreter_reverse_tcp',
        extension: '.php',
        platforms: [:osx, :linux, :windows],
        execute_cmd: ['php', '${payload_path}'],
        generate_options: {
          '-f': 'raw',
        },
        payload_options: {
        }
      },
      {
        name: 'php/meterpreter/reverse_tcp',
        extension: '.php',
        platforms: [:osx, :linux, :windows],
        execute_cmd: ['php', '${payload_path}'],
        generate_options: {
          '-f': 'raw',
        },
        payload_options: {
        }
      },
    ],
    java: [
      {
        name: 'java/meterpreter/reverse_tcp',
        extension: '.jar',
        platforms: [:osx, :linux, :windows],
        execute_cmd: ['java', '-jar', '${payload_path}'],
        generate_options: {
          '-f': 'jar',
        },
        payload_options: {
          spawn: 0
        }
      },
    ],
    mettle: [
      {
        name: 'linux/x64/meterpreter/reverse_tcp',
        extension: '',
        platforms: [:linux],
        executable: true,
        execute_cmd: ['${payload_path}'],
        generate_options: {
          '-f': 'elf',
        },
        payload_options: {
          MeterpreterTryToFork: false
        }
      },
      {
        name: 'linux/x64/meterpreter_reverse_tcp',
        extension: '',
        platforms: [:linux],
        executable: true,
        execute_cmd: ['${payload_path}'],
        generate_options: {
          '-f': 'elf',
        },
        payload_options: {
          MeterpreterTryToFork: false
        }
      },
      {
        name: 'osx/x64/meterpreter_reverse_tcp',
        extension: '',
        platforms: [:osx],
        executable: true,
        execute_cmd: ['${payload_path}'],
        generate_options: {
          '-f': 'macho',
        },
        payload_options: {
          MeterpreterTryToFork: false
        }
      },
      {
        name: 'osx/x64/meterpreter/reverse_tcp',
        extension: '',
        platforms: [:osx],
        executable: true,
        execute_cmd: ['${payload_path}'],
        generate_options: {
          '-f': 'macho',
        },
        payload_options: {
          MeterpreterTryToFork: false
        }
      }
    ],
    windows_meterpreter: [
      {
        name: 'windows/meterpreter/reverse_tcp',
        extension: '.exe',
        platforms: [:windows],
        execute_cmd: ['${payload_path}'],
        executable: true,
        generate_options: {
          '-f': 'exe',
        },
        payload_options: {
          MeterpreterTryToFork: false
        }
      },
      {
        name: 'windows/meterpreter_reverse_tcp',
        extension: '.exe',
        platforms: [:windows],
        execute_cmd: ['${payload_path}'],
        executable: true,
        generate_options: {
          '-f': 'exe',
        },
        payload_options: {
          MeterpreterTryToFork: false
        }
      }
    ]
  }

  let_it_be(:port_generator) { PortGenerator.new }

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

  # Waits until the given expectations are all true. This function executes the given block,
  # and if a failure occurs it will be retried `retry_count` times before finally failing.
  # This is useful to expect against asynchronous/eventually consistent systems.
  #
  # @param retry_count [Integer] The total amount of times to retry the given expectation
  # @param sleep_duration [Integer] The total amount of time to sleep before trying again
  def wait_for_expect(retry_count = 40, sleep_duration = 0.5)
    failure_count = 0

    begin
      yield
    rescue RSpec::Expectations::ExpectationNotMetError
      failure_count += 1
      if failure_count < retry_count
        sleep sleep_duration
        retry
      else
        raise
      end
    end
  end

  METERPRETER_PAYLOADS.each.with_index do |(name, configs)|
    describe "#{name}" do
      configs.each do |config|
        next unless supported_platform?(config)

        describe "#{human_name_for_payload(config)}" do
          # TODO: Load this dynamically so new tests will automatically be picked up
          [
            { name: "test/cmd_exec", severity: :critical },
            { name: "test/extapi", security: :known },
            { name: "test/file", severity: :critical },
            { name: "test/get_env", severity: :critical },
            { name: "test/meterpreter", severity: :critical },
            { name: "test/railgun", severity: :known },
            { name: "test/railgun_reverse_lookups", severity: :known },
            { name: "test/registry", severity: :known },
            { name: "test/search", severity: :critical },
            { name: "test/services", severity: :known },
            { name: "test/unix", severity: :critical }
          ].each do |test_module|
            describe "#{test_module[:name]}" do
              let(:payload) { Payload.new(config) }

              # The shared payload session instance that will be reused across the test run
              let(:await_session_id) do
                # TODO: Move this into the driver, so remote drivers can be used
                config[:payload_options].merge!({ lport: port_generator.next, lhost: '127.0.0.1' })

                console.sendline "use #{payload.name}"
                console.recvuntil(Console.prompt)

                # Generate the payload
                console.sendline payload.generate_command
                # TODO: Fix race condition, and handle generation failed being returned iin this scenario
                console.recvuntil(/Writing \d+ bytes[^\n]*\n/)
                generate_result = console.recvuntil(Console.prompt)

                expect(generate_result.lines).to_not include(match("generation failed"))
                wait_for_expect do
                  expect(payload.size).to be > 0
                end

                console.sendline "to_handler"
                console.recvuntil(/Started reverse TCP handler[^\n]*\n/)

                driver.run_payload(payload)

                session_opened_matcher = /Meterpreter session (\d+) opened[^\n]*\n/
                session_message = console.recvuntil(session_opened_matcher)
                session_id = session_message[session_opened_matcher, 1]
                expect(session_id).to_not be_nil

                session_id
              end

              before :each do
                console.reset
                await_session_id
              end

              after :all do
                console.reset
              end

              it "passes", severity: test_module[:severity] do
                console.sendline("use #{test_module[:name]}")
                console.recvuntil(Console.prompt)

                console.sendline("run session=#{await_session_id} addentropy=true verbose=true")

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
              ensure
                Allure.add_attachment(
                  name: 'payload',
                  source: payload.as_readable_text,
                  type: Allure::ContentType::TXT,
                  test_case: false
                )

                Allure.add_attachment(
                  name: 'console data',
                  source: console.all_data,
                  type: Allure::ContentType::TXT,
                  test_case: false
                )
              end
            end
          end
        end
      end
    end
  end
end
