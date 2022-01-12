module Acceptance
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

      @default_timeout = ENV['CI'] ? 30 : 15
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

      stdin.sync = true
      stdout_and_stderr.sync = true
    rescue StandardError => e
      warn "popen failure #{e}"
      raise
    end

    def recvline(timeout: @default_timeout)
      recvuntil($INPUT_RECORD_SEPARATOR, timeout: timeout)
    end

    alias readline recvline

    # @param [String|Regexp] delim
    def recvuntil(delim, timeout: @default_timeout, drop_delim: false)
      buffer = ''
      result = nil

      with_countdown(timeout) do |countdown|
        while alive? && !countdown.elapsed?
          data_chunk = recv(timeout: [countdown.remaining_time, 1].min)
          if !data_chunk
            next
          end

          buffer += data_chunk
          has_delimiter = delim.is_a?(Regexp) ? buffer.match?(delim) : buffer.include?(delim)
          next unless has_delimiter

          result, matched_delim, remaining = buffer.partition(delim)
          unless drop_delim
            result += matched_delim
          end
          unrecv(remaining)
          # clear our temporary buffer
          buffer = ''

          return result
        end
      ensure
        unrecv(buffer)
      end

      result
    end

    def recvall(timeout: @default_timeout)
      result = ''

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

    def recv(size = 4096, timeout: @default_timeout)
      buffer_result = buffer.read(size)
      return buffer_result if buffer_result

      retry_count = 0

      # Eagerly read, and if we fail - await a response within the given timeout period
      begin
        result = stdout_and_stderr.read_nonblock(size)
        if !result.nil?
          log("[read] #{result}")
          @all_data.write(result)
        end
      rescue IO::WaitReadable
        IO.select([stdout_and_stderr], nil, nil, timeout)
        retry_count += 1
        retry if retry_count == 1
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
          ready = IO.select([stdout_and_stderr, $stdin], [], [], 10)

          next unless ready

          reads, = ready

          reads.to_a.each do |read|
            case read
            when $stdin
              input = $stdin.gets
              if input.chomp == '!continue'
                return
              elsif input.chomp == '!exit'
                exit
              end

              write(input)
            when stdout_and_stderr
              $stdout.write(recv(2048))
              $stdout.flush
            end
          end
        end
      end
    end

    def close
      stdin.close
      stdout_and_stderr.close
      begin
        Process.kill('KILL', wait_thread.pid) if wait_thread.pid
      rescue StandardError => e
        warn "error #{e} for #{@cmd}, pid #{wait_thread.pid}"
      end
    end

    attr_reader :stdin, :stdout_and_stderr, :wait_thread

    private

    attr_reader :buffer
    attr_writer :stdin, :stdout_and_stderr, :wait_thread

    def log(s)
      return unless @debug

      $stderr.puts s
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
      if countdown.elapsed?
        raise "Failed await result, remaining buffer: #{buffer.string[buffer.pos..-1].inspect}"
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
    rescue StandardError => _e
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
      default_payload_options = {
        AutoVerifySessionTimeout: 10
      }
      payload_options = default_payload_options.merge(@payload_options)
      generate_options = @generate_options.map do |key, value|
        "#{key} #{value}"
      end
      payload_options = payload_options.map do |key, value|
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
      @payload_processes = []

      ObjectSpace.define_finalizer(self, proc { close })
    end

    # @param [Payload] payload
    def run_payload(payload)
      if payload.executable? && !File.executable?(payload.path)
        FileUtils.chmod('+x', payload.path)
      end

      payload_process = PayloadProcess.new(payload.execute_command)
      puts 'spawning before'
      payload_process.run
      puts 'spawning after'
      @payload_processes << payload_process
    end

    def open_console
      @console = Console.new
      @console.run
      @console.recvuntil(Console.prompt, timeout: 120)

      @console
    end

    def close_payloads
      close_processes(@payload_processes)
    end

    def close
      close_processes(@payload_processes + [console])
    end

    private

    def close_processes(processes)
      while (process = processes.pop)
        begin
          process.close
        rescue StandardError => e
          warn e.to_s
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
        'PATH' => "#{framework_root.shellescape}:#{ENV['PATH']}"
      }
      @cmd = [
        'bundle', 'exec', 'ruby', 'msfconsole.rb',
        '--no-readline',
        # '--logger', 'Stdout',
        '--quiet'
      ]
      @options = {
        chdir: framework_root
      }
    end

    def self.prompt
      /msf6.*>\s+/
    end

    def reset
      sendline('sessions -K')
      recvuntil(Console.prompt)

      sendline('jobs -K')
      recvuntil(Console.prompt)

      @all_data.reopen('')
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

  class LineValidation
    # @param [string|Array<String>] values A line string, or array of lines
    # @param [Object] options Additional options for configuring this failure, i.e. if it's a known flaky test result etc.
    def initialize(values, options = {})
      @values = Array(values)
      @options = options
    end

    def flatten
      @values.map { |value| self.class.new(value, @options) }
    end

    def value
      raise StandardError, "More than one value present" if @values.length > 1
      @values[0]
    end

    # @return [boolean] returns true if the current failure applies under the current environment or the result is flaky, false otherwise.
    def flaky?
      !!@options.fetch(:flaky, true)
    end

    # @return [boolean] returns true if the current failure applies under the current environment or the result is flaky, false otherwise.
    def if?
      !!@options.fetch(:if, true)
    end
  end
end
