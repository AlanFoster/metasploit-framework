require 'readline'

loop do
  puts "\nCurrent time: #{Time.now}"
  STDOUT.write "prompt > "
  STDOUT.flush

  # readers, _writers, _errors, = IO.select([STDIN], [], [], 2)
  # readers.to_a.each do |reader|
    puts "User message: #{STDIN.gets}"
  # end
end
