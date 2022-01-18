# # -*- coding: binary -*-
# require 'stringio'
# require 'factory_bot'
#
# ENV['RAILS_ENV'] = 'test'
#
# # @note must be before loading config/environment because railtie needs to be loaded before
# #   `Metasploit::Framework::Application.initialize!` is called.
# #
# # Must be explicit as activerecord is optional dependency
# require 'active_record/railtie'
# require 'rubocop'
# require 'rubocop/rspec/support'
# require 'metasploit/framework/database'
# # check if database.yml is present
# unless Metasploit::Framework::Database.configurations_pathname.try(:to_path)
#   fail 'RSPEC currently needs a configured database'
# end
#
# require File.expand_path('../../config/environment', __FILE__)
#
# # Don't `require 'rspec/rails'` as it includes support for pieces of rails that metasploit-framework doesn't use
# require 'rspec/rails'
#
# require 'metasploit/framework/spec'
#
# FILE_FIXTURES_PATH = File.expand_path(File.dirname(__FILE__)) + '/file_fixtures/'
#
# # Load the shared examples from the following engines
# engines = [
#   Metasploit::Concern,
#   Rails
# ]
#
# # Requires supporting ruby files with custom matchers and macros, etc,
# # in spec/support/ and its subdirectories.
# engines.each do |engine|
#   support_glob = engine.root.join('spec', 'support', '**', '*.rb')
#   Dir[support_glob].each { |f|
#     require f
#   }
# end
#
# RSpec.configure do |config|
#   config.raise_errors_for_deprecations!
#   config.include RuboCop::RSpec::ExpectOffense
#   config.expose_dsl_globally = false
#
#   # These two settings work together to allow you to limit a spec run
#   # to individual examples or groups you care about by tagging them with
#   # `:focus` metadata. When nothing is tagged with `:focus`, all examples
#   # get run.
#   if ENV['CI']
#     config.before(:example, :focus) { raise "Should not commit focused specs" }
#   else
#     config.filter_run focus: true
#     config.run_all_when_everything_filtered = true
#   end
#
#   # allow more verbose output when running an individual spec file.
#   if config.files_to_run.one?
#     # RSpec filters the backtrace by default so as not to be so noisy.
#     # This causes the full backtrace to be printed when running a single
#     # spec file (e.g. to troubleshoot a particular spec failure).
#     config.full_backtrace = true
#   end
#
#   # Print the 10 slowest examples and example groups at the
#   # end of the spec run, to help surface which specs are running
#   # particularly slow.
#   config.profile_examples = 10
#
#   # Run specs in random order to surface order dependencies. If you find an
#   # order dependency and want to debug it, you can fix the order by providing
#   # the seed, which is printed after each run.
#   #     --seed 1234
#   config.order = :random
#
#   config.use_transactional_fixtures = true
#
#   # Seed global randomization in this process using the `--seed` CLI option.
#   # Setting this allows you to use `--seed` to deterministically reproduce
#   # test failures related to randomization by passing the same `--seed` value
#   # as the one that triggered the failure.
#   Kernel.srand config.seed
#
#   # Implemented to avoid regression issue with code calling Faker not being deterministic
#   # https://github.com/faker-ruby/faker/issues/2281
#   Faker::Config.random = Random.new(config.seed)
#
#   config.expect_with :rspec do |expectations|
#     # Enable only the newer, non-monkey-patching expect syntax.
#     expectations.syntax = :expect
#   end
#
#   # rspec-mocks config goes here. You can use an alternate test double
#   # library (such as bogus or mocha) by changing the `mock_with` option here.
#   config.mock_with :rspec do |mocks|
#     # Enable only the newer, non-monkey-patching expect syntax.
#     # For more details, see:
#     #   - http://teaisaweso.me/blog/2013/05/27/rspecs-new-message-expectation-syntax/
#     mocks.syntax = :expect
#
#     mocks.patch_marshal_to_support_partial_doubles = false
#
#     # Prevents you from mocking or stubbing a method that does not exist on
#     # a real object.
#     mocks.verify_partial_doubles = true
#   end
#
#   # rspec-rails 3 will no longer automatically infer an example group's spec type
#   # from the file location. You can explicitly opt-in to the feature using this
#   # config option.
#   # To explicitly tag specs without using automatic inference, set the `:type`
#   # metadata manually:
#   #
#   #     describe ThingsController, :type => :controller do
#   #       # Equivalent to being in spec/controllers
#   #     end
#   config.infer_spec_type_from_file_location!
#
#   if ENV['REMOTE_DB']
#     require 'metasploit/framework/data_service/remote/managed_remote_data_service'
#     opts = {}
#     opts[:process_name] = File.join('tools', 'dev', 'msfdb_ws')
#     opts[:host] = 'localhost'
#     opts[:port] = '8080'
#
#     config.before(:suite) do
#       Metasploit::Framework::DataService::ManagedRemoteDataService.instance.start(opts)
#     end
#
#     config.after(:suite) do
#       Metasploit::Framework::DataService::ManagedRemoteDataService.instance.stop
#     end
#   end
#
# end
#
# Metasploit::Framework::Spec::Constants::Suite.configure!
# Metasploit::Framework::Spec::Threads::Suite.configure!
#
# def get_stdout(&block)
#   out = $stdout
#   $stdout = tmp = StringIO.new
#   begin
#     yield
#   ensure
#     $stdout = out
#   end
#   tmp.string
# end
#
# def get_stderr(&block)
#   out = $stderr
#   $stderr = tmp = StringIO.new
#   begin
#     yield
#   ensure
#     $stderr = out
#   end
#   tmp.string
# end

require "allure-rspec"
require 'test_prof/recipes/rspec/let_it_be'

class TeeStringIO
  def initialize(stream)
    @stream = stream
    @buffer = StringIO::new
  end

  def string
    @buffer.string
  end

  def respond_to?(method_name, include_private = false)
    @stream.respond_to?(method_name, include_private)
  end

  def method_missing(method_name, *args)
    @stream.send(method_name, *args)
    @buffer.send(method_name, *args)
  end
end

class MetasploitTransactionAdapter
  # before_all adapters must implement two methods:
  # - begin_transaction
  # - rollback_transaction
  def begin_transaction
    # TODO: Ensure sessions are killed?
  end

  def rollback_transaction
    # TODO: Ensure sessions are killed?
  end
end

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
  config.environment_properties = {
    host_os: RbConfig::CONFIG['host_os'],
    ruby_version: RUBY_VERSION
  }
  # categories.json
  # config.categories = File.new("my_custom_categories.json")
end

# This file was generated by the `rspec --init` command. Conventionally, all
# specs live under a `spec` directory, which RSpec adds to the `$LOAD_PATH`.
# The generated `.rspec` file contains `--require spec_helper` which will cause
# this file to always be loaded, without a need to explicitly require it in any
# files.
#
# Given that it is always loaded, you are encouraged to keep this file as
# light-weight as possible. Requiring heavyweight dependencies from this file
# will add to the boot time of your test suite on EVERY test run, even for an
# individual file that may not need all of that loaded. Instead, consider making
# a separate helper file that requires the additional dependencies and performs
# the additional setup, and require it from the spec files that actually need
# it.
#
# See http://rubydoc.info/gems/rspec-core/RSpec/Core/Configuration
RSpec.configure do |config|
  TestProf::BeforeAll.adapter = MetasploitTransactionAdapter.new

  # register around filter that captures stdout and stderr
  # config.around(:each) do |example|
  #   old_stdout = STDOUT
  #   old_stderr = STDERR
  #
  #   $stdout = TeeStringIO.new(old_stdout)
  #   $stderr = TeeStringIO.new(old_stderr)
  #
  #   example.run
  #
  #   example.metadata[:stdout] = $stdout.string
  #   example.metadata[:stderr] = $stderr.string
  #
  #   $stdout = old_stdout
  #   $stderr = old_stderr
  # end


  # rspec-expectations config goes here. You can use an alternate
  # assertion/expectation library such as wrong or the stdlib/minitest
  # assertions if you prefer.
  config.expect_with :rspec do |expectations|
    # This option will default to `true` in RSpec 4. It makes the `description`
    # and `failure_message` of custom matchers include text for helper methods
    # defined using `chain`, e.g.:
    #     be_bigger_than(2).and_smaller_than(4).description
    #     # => "be bigger than 2 and smaller than 4"
    # ...rather than:
    #     # => "be bigger than 2"
    expectations.include_chain_clauses_in_custom_matcher_descriptions = true
  end

  # rspec-mocks config goes here. You can use an alternate test double
  # library (such as bogus or mocha) by changing the `mock_with` option here.
  config.mock_with :rspec do |mocks|
    # Prevents you from mocking or stubbing a method that does not exist on
    # a real object. This is generally recommended, and will default to
    # `true` in RSpec 4.
    mocks.verify_partial_doubles = true
  end

  # This option will default to `:apply_to_host_groups` in RSpec 4 (and will
  # have no way to turn it off -- the option exists only for backwards
  # compatibility in RSpec 3). It causes shared context metadata to be
  # inherited by the metadata hash of host groups and examples, rather than
  # triggering implicit auto-inclusion in groups with matching metadata.
  config.shared_context_metadata_behavior = :apply_to_host_groups

  # The settings below are suggested to provide a good initial experience
  # with RSpec, but feel free to customize to your heart's content.
=begin
  # This allows you to limit a spec run to individual examples or groups
  # you care about by tagging them with `:focus` metadata. When nothing
  # is tagged with `:focus`, all examples get run. RSpec also provides
  # aliases for `it`, `describe`, and `context` that include `:focus`
  # metadata: `fit`, `fdescribe` and `fcontext`, respectively.
  config.filter_run_when_matching :focus
  # Allows RSpec to persist some state between runs in order to support
  # the `--only-failures` and `--next-failure` CLI options. We recommend
  # you configure your source control system to ignore this file.
  config.example_status_persistence_file_path = "spec/examples.txt"
  # Limits the available syntax to the non-monkey patched syntax that is
  # recommended. For more details, see:
  #   - http://rspec.info/blog/2012/06/rspecs-new-expectation-syntax/
  #   - http://www.teaisaweso.me/blog/2013/05/27/rspecs-new-message-expectation-syntax/
  #   - http://rspec.info/blog/2014/05/notable-changes-in-rspec-3/#zero-monkey-patching-mode
  config.disable_monkey_patching!
  # This setting enables warnings. It's recommended, but in some cases may
  # be too noisy due to issues in dependencies.
  config.warnings = true
  # Many RSpec users commonly either run the entire suite or an individual
  # file, and it's useful to allow more verbose output when running an
  # individual spec file.
  if config.files_to_run.one?
    # Use the documentation formatter for detailed output,
    # unless a formatter has already been configured
    # (e.g. via a command-line flag).
    config.default_formatter = "doc"
  end
  # Print the 10 slowest examples and example groups at the
  # end of the spec run, to help surface which specs are running
  # particularly slow.
  config.profile_examples = 10
  # Run specs in random order to surface order dependencies. If you find an
  # order dependency and want to debug it, you can fix the order by providing
  # the seed, which is printed after each run.
  #     --seed 1234
  config.order = :random
  # Seed global randomization in this process using the `--seed` CLI option.
  # Setting this allows you to use `--seed` to deterministically reproduce
  # test failures related to randomization by passing the same `--seed` value
  # as the one that triggered the failure.
  Kernel.srand config.seed
=end
end
