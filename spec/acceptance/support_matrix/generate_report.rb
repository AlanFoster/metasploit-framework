require 'json'
require 'erb'

$:.unshift(File.join(__dir__, '..', '..', '..', 'lib'))
require 'msfenv'

module ReportGeneration
  class SupportMatrix
    def initialize(data)
      @data = data
    end

    def generation_date
      Time.now.strftime("%FT%T")
    end

    def table
      columns = [""] + @data[:sessions].map do |session|
        session[:session_type]
      end
      all_commands = Rex::Post::Meterpreter::CommandMapper.get_command_names

      # Group into buckets, and priortize sort order
      order_preference = [
        # MVP Meterpreter
        "core",
        "stdapi",

        # Remaining
        "sniffer",
        "extapi",
        "kiwi",
        "python",
        "unhook",
        "appapi",
        "winpmem",
        "powershell",
        "lanattacks",
        "priv",
        "incognito",
        "peinjector",
        "espia",
        "android",
      ]

      ordered_commands = all_commands.sort_by do |command|
        command_prefix = command.split("_").first
        sort_index = order_preference.index(command_prefix)

        sort_index
      end

      # Map of session type, to supported commands. i.e. { osx: { command_name_1: true } }
      sessions_to_supported_commands_hash = @data[:sessions].each_with_object({}) do |session, hash|
        session_type = session[:session_type]
        # Map command name to its availability
        supported_command_map = session[:commands].each_with_object({}) do |command, map|
          command_name = command[:name]
          map[command_name] = true
        end
        hash[session_type] = supported_command_map
      end

      rows = ordered_commands.map do |command|
        session_supported_cells = sessions_to_supported_commands_hash.map do |(_session, compatibility)|
          compatibility.include?(command)
        end

        [command] + session_supported_cells
      end

      {
        columns: columns,
        rows: rows
      }
    end

    def get_binding
      binding
    end
  end

  def self.generate(data_path, output_path)
    data = JSON.parse(File.read(data_path), symbolize_names: true)
    template = File.read(File.join(File.dirname(__FILE__),'template.erb'))
    renderer = ERB.new(template, trim_mode: '-')
    support_matrix = SupportMatrix.new(data)

    result = renderer.result(support_matrix.get_binding)
    File.open(output_path, "wb") do |f|
      f.write(result)
    end
  end
end

if $PROGRAM_NAME == __FILE__
  ReportGeneration.generate(
    File.expand_path("results.json", __dir__),
    File.expand_path("result.html", __dir__)
  )
end
