$:.unshift(File.join(__dir__, '..', '..', '..', 'spec'))
$:.unshift(File.join(__dir__, '..', '..', '..', 'lib'))

require 'allure_config'
require 'json'
require 'erb'
require 'optparse'
# require 'msfenv'

module ReportGeneration
  class SupportMatrix
    def initialize(data)
      @data = data
    end

    def generation_date
      Time.now.strftime("%FT%T")
    end

    def table
      preferred_session_name_order = [
        "java/linux",
        "java/osx",
        "java/windows",

        "php/linux",
        "php/osx",
        "php/windows",

        "python/linux",
        "python/osx",
        "python/windows",

        "x86/linux",
        "x64/linux",

        "x64/osx",

        "x86/windows",
        "x64/windows",
      ]

      sorted_sessions = @data.fetch(:sessions, []).sort_by { |session| preferred_session_name_order.index(session[:session_type]) }
      sorted_session_names = sorted_sessions.map do |session|
        session[:session_type]
      end

      # all_commands = Rex::Post::Meterpreter::CommandMapper.get_command_names
      all_commands = ["core_channel_open", "core_channel_read", "core_channel_seek", "core_channel_tell", "core_channel_write", "core_console_write", "core_enumextcmd", "core_get_session_guid", "core_machine_id", "core_migrate", "core_native_arch", "core_negotiate_tlv_encryption", "core_pivot_add", "core_pivot_remove", "core_pivot_session_died", "core_set_session_guid", "core_set_uuid", "core_shutdown", "core_transport_add", "core_transport_change", "core_transport_getcerthash", "core_transport_list", "core_transport_next", "core_transport_prev", "core_transport_remove", "core_transport_setcerthash", "core_transport_set_timeouts", "core_transport_sleep", "core_pivot_session_new", "core_channel_close", "core_channel_interact", "core_loadlib", "core_patch_url", "core_channel_eof", "sniffer_capture_stop", "sniffer_capture_stats", "sniffer_capture_release", "sniffer_capture_dump", "sniffer_capture_dump_read", "sniffer_interfaces", "sniffer_capture_start", "extapi_adsi_domain_query", "extapi_clipboard_get_data", "extapi_clipboard_monitor_dump", "extapi_clipboard_monitor_pause", "extapi_clipboard_monitor_purge", "extapi_clipboard_monitor_resume", "extapi_clipboard_monitor_start", "extapi_clipboard_monitor_stop", "extapi_clipboard_set_data", "extapi_ntds_parse", "extapi_pageant_send_query", "extapi_service_control", "extapi_service_enum", "extapi_service_query", "extapi_window_enum", "extapi_wmi_query", "kiwi_exec_cmd", "python_reset", "python_execute", "unhook_pe", "appapi_app_install", "appapi_app_run", "appapi_app_list", "appapi_app_uninstall", "winpmem_dump_ram", "powershell_assembly_load", "powershell_session_remove", "powershell_execute", "powershell_shell", "lanattacks_add_tftp_file", "lanattacks_dhcp_log", "lanattacks_reset_dhcp", "lanattacks_reset_tftp", "lanattacks_set_dhcp_option", "lanattacks_start_dhcp", "lanattacks_start_tftp", "lanattacks_stop_dhcp", "lanattacks_stop_tftp", "priv_passwd_get_sam_hashes", "priv_fs_blank_directory_mace", "priv_fs_blank_file_mace", "priv_fs_get_file_mace", "priv_fs_set_file_mace", "priv_fs_set_file_mace_from_file", "priv_elevate_getsystem", "incognito_list_tokens", "incognito_impersonate_token", "incognito_add_user", "incognito_add_group_user", "incognito_add_localgroup_user", "incognito_snarf_hashes", "android_device_shutdown", "android_set_audio_mode", "android_interval_collect", "android_dump_sms", "android_dump_contacts", "android_geolocate", "android_dump_calllog", "android_check_root", "android_hide_app_icon", "android_activity_start", "android_set_wallpaper", "android_send_sms", "android_wlan_geolocate", "android_sqlite_query", "android_wakelock", "peinjector_inject_shellcode", "stdapi_fs_chmod", "stdapi_fs_chdir", "stdapi_fs_delete_dir", "stdapi_fs_delete_file", "stdapi_fs_file_copy", "stdapi_fs_file_expand_path", "stdapi_fs_file_move", "stdapi_fs_getwd", "stdapi_fs_ls", "stdapi_fs_md5", "stdapi_fs_mkdir", "stdapi_fs_mount_show", "stdapi_fs_search", "stdapi_fs_separator", "stdapi_fs_sha1", "stdapi_fs_stat", "stdapi_net_config_add_route", "stdapi_net_config_get_arp_table", "stdapi_net_config_get_interfaces", "stdapi_net_config_get_netstat", "stdapi_net_config_get_proxy", "stdapi_net_config_get_routes", "stdapi_net_config_remove_route", "stdapi_net_resolve_host", "stdapi_net_resolve_hosts", "stdapi_net_socket_tcp_shutdown", "stdapi_net_tcp_channel_open", "stdapi_railgun_api", "stdapi_railgun_api_multi", "stdapi_railgun_memread", "stdapi_railgun_memwrite", "stdapi_registry_check_key_exists", "stdapi_registry_close_key", "stdapi_registry_create_key", "stdapi_registry_delete_key", "stdapi_registry_delete_value", "stdapi_registry_enum_key", "stdapi_registry_enum_key_direct", "stdapi_registry_enum_value", "stdapi_registry_enum_value_direct", "stdapi_registry_load_key", "stdapi_registry_open_key", "stdapi_registry_open_remote_key", "stdapi_registry_query_class", "stdapi_registry_query_value", "stdapi_registry_query_value_direct", "stdapi_registry_set_value", "stdapi_registry_set_value_direct", "stdapi_registry_unload_key", "stdapi_sys_config_driver_list", "stdapi_sys_config_drop_token", "stdapi_sys_config_getenv", "stdapi_sys_config_getprivs", "stdapi_sys_config_getsid", "stdapi_sys_config_getuid", "stdapi_sys_config_localtime", "stdapi_sys_config_rev2self", "stdapi_sys_config_steal_token", "stdapi_sys_config_sysinfo", "stdapi_sys_eventlog_clear", "stdapi_sys_eventlog_close", "stdapi_sys_eventlog_numrecords", "stdapi_sys_eventlog_oldest", "stdapi_sys_eventlog_open", "stdapi_sys_eventlog_read", "stdapi_sys_power_exitwindows", "stdapi_sys_process_attach", "stdapi_sys_process_close", "stdapi_sys_process_execute", "stdapi_sys_process_get_info", "stdapi_sys_process_get_processes", "stdapi_sys_process_getpid", "stdapi_sys_process_image_get_images", "stdapi_sys_process_image_get_proc_address", "stdapi_sys_process_image_load", "stdapi_sys_process_image_unload", "stdapi_sys_process_kill", "stdapi_sys_process_memory_allocate", "stdapi_sys_process_memory_free", "stdapi_sys_process_memory_lock", "stdapi_sys_process_memory_protect", "stdapi_sys_process_memory_query", "stdapi_sys_process_memory_read", "stdapi_sys_process_memory_unlock", "stdapi_sys_process_memory_write", "stdapi_sys_process_thread_close", "stdapi_sys_process_thread_create", "stdapi_sys_process_thread_get_threads", "stdapi_sys_process_thread_open", "stdapi_sys_process_thread_query_regs", "stdapi_sys_process_thread_resume", "stdapi_sys_process_thread_set_regs", "stdapi_sys_process_thread_suspend", "stdapi_sys_process_thread_terminate", "stdapi_sys_process_wait", "stdapi_ui_desktop_enum", "stdapi_ui_desktop_get", "stdapi_ui_desktop_screenshot", "stdapi_ui_desktop_set", "stdapi_ui_enable_keyboard", "stdapi_ui_enable_mouse", "stdapi_ui_get_idle_time", "stdapi_ui_get_keys_utf8", "stdapi_ui_send_keyevent", "stdapi_ui_send_keys", "stdapi_ui_send_mouse", "stdapi_ui_start_keyscan", "stdapi_ui_stop_keyscan", "stdapi_ui_unlock_desktop", "stdapi_webcam_audio_record", "stdapi_webcam_get_frame", "stdapi_webcam_list", "stdapi_webcam_start", "stdapi_webcam_stop", "stdapi_audio_mic_start", "stdapi_audio_mic_stop", "stdapi_audio_mic_list", "stdapi_sys_process_set_term_size", "espia_image_get_dev_screen"]

      # Group into buckets, and priortize sort order
      extension_names = [
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
        sort_index = extension_names.index(command_prefix)

        sort_index
      end

      # Map session type to supported commands. i.e. { osx: { command_name_1: true } }
      sessions_to_supported_commands_hash = sorted_sessions.each_with_object({}) do |session, hash|
        session_type = session[:session_type]
        # Map command name to its availability
        supported_command_map = session[:commands].each_with_object({}) do |command, map|
          command_name = command[:name]
          map[command_name] = true
        end
        hash[session_type] = supported_command_map
      end

      columns = [""] + sorted_session_names
      rows = extension_names.map do |extension_name|
        extension_commands = ordered_commands.select { |command| command.start_with?(extension_name) }

        command_rows = extension_commands.map do |command|
          session_supported_cells = sessions_to_supported_commands_hash.map do |(_session, compatibility)|
            compatibility.include?(command)
          end

          [command] + session_supported_cells
        end
        extension_coverage = sessions_to_supported_commands_hash.map do |(_session, compatibility)|
          implemented_count = extension_commands.select { |command| compatibility.include?(command) }.size
          total_count = extension_commands.size
          percentage = ((implemented_count.to_f / total_count.to_f) * 100).to_i

          "#{percentage}%"
        end

        {
          heading: [extension_name] + extension_coverage,
          values: command_rows
        }
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

  def self.extract_data(options)
    if options[:allure_data]
      results_directory = options[:allure_data]
      test_result_files = Dir["**/*-result.json", base: results_directory]
      meterpreter_compatibility_results = test_result_files.filter_map do |test_result_file|
        path = File.join(results_directory, test_result_file)
        json = JSON.parse(File.read(path), symbolize_names: true)

        compatibility_attachment = json.fetch(:attachments, [])
                                   .find { |attachment| attachment[:name] == 'available commands' }
        next unless compatibility_attachment

        compatibility_attachment_path = File.join(File.dirname(path), compatibility_attachment[:source])
        JSON.parse(File.read(compatibility_attachment_path), symbolize_names: true)
      end

      aggregated_data = meterpreter_compatibility_results.each_with_object({}) do |data, aggregate|
        aggregate[:sessions] ||= []
        aggregate[:sessions] += data[:sessions]
      end

      aggregated_data
    else
      data_path = options.fetch(:data_path)
      data = JSON.parse(File.read(data_path), symbolize_names: true)

      data
    end
  end

  def self.generate(options)
    data = self.extract_data(options)

    template = File.read(File.join(File.dirname(__FILE__),'template.erb'))
    renderer = ERB.new(template, trim_mode: '-')
    support_matrix = SupportMatrix.new(data)

    result = renderer.result(support_matrix.get_binding)
    STDOUT.write(result)
  end
end

if $PROGRAM_NAME == __FILE__
  options = {}
  options_parser = OptionParser.new do |opts|
    opts.banner = "Usage: #{File.basename(__FILE__)} [options]"

    opts.on '-h', '--help', 'Help banner.' do
      return print(opts.help)
    end

    opts.on('--allure-data [path]', 'Use allure as the data source') do |allure_data|
      allure_data ||= AllureRspec.configuration.results_directory
      options[:allure_data] = allure_data
    end

    opts.on('--data-path', 'The path to the report generated by scripts/resource/meterpreter_compatibility.rc') do |data_path|
      options[:skip_migration] = data_path
    end
  end
  options_parser.parse!

  ReportGeneration.generate(options)
end
