## Acceptance Tests

A slower test suite that ensures high level functionality works as expected,
such verifying msfconsole opens successfully, and can generate Meterpreter payloads,
handlers, etc.

### Examples

Running Meterpreter test suite:

```
bundle exec rspec './spec/acceptance/meterpreter_spec.rb'
```

Running one test:
```

```

Running only the PHP Meterpreter test suite on Unix / Windows:
```
METERPRETER=php bundle exec rspec './spec/acceptance/meterpreter_spec.rb'

$env:METERPRETER = 'php'; bundle exec rspec './spec/acceptance/meterpreter_spec.rb'
```

### Debugging
