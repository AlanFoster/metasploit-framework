require "allure-rspec"

AllureRspec.configure do |config|
  config.results_directory = "tmp/allure-raw-data"
  config.clean_results_directory = true
  config.logging_level = Logger::INFO
  config.logger = Logger.new($stdout, Logger::DEBUG)
  config.environment = RbConfig::CONFIG['host_os']

  # these are used for creating links to bugs or test cases where {} is replaced with keys of relevant items
  # config.link_tms_pattern = "http://www.jira.com/browse/{}"
  # config.link_issue_pattern = "http://www.jira.com/browse/{}"

  # additional metadata
  # environment.properties
  environment_properties = {
    host_os: RbConfig::CONFIG['host_os'],
    ruby_version: RUBY_VERSION
  }.compact
  meterpreter_name = ENV['METERPRETER']
  meterpreter_runtime_version = ENV['METERPRETER_RUNTIME_VERSION']
  if meterpreter_name.present?
    environment_properties[:meterpreter_name] = meterpreter_name
    if meterpreter_runtime_version.present?
      environment_properties[:meterpreter_runtime_version] = "#{meterpreter_name}#{meterpreter_runtime_version}"
    end
  end

  config.environment_properties = environment_properties.compact
  # categories.json
  # config.categories = File.new("my_custom_categories.json")
end
