##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'

class Metasploit4 < Msf::Auxiliary
	include Msf::Exploit::Remote::Tcp
	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::Report

	def initialize()
		super(
			'Name'           => 'RealVNC NULL Authentication Mode Scanner',
			'Version'	 => '',
			'Description'    => %q{
				This module scans for RealVNC servers vulnerable to the
				NULL authentication mode vulnerability.
			},
			'Author'         =>
				[
					'syntaxerr <chris@erroredsecurity.com>'
				],
			'License'        => MSF_LICENSE,
			'References'     =>
				[
					['BID', '17978'],
					['OSVDB', '25479'],
					['URL', 'http://secunia.com/advisories/20107/'],
					['CVE', '2006-2369'],
				],
			'DisclosureDate' => 'May 15 2006')

		register_options(
			[
				Opt::RPORT(5900)
			], self.class)
	end

	def run_host(ip)

		res = connect
		gethello = res.get_once
		if gethello.include? "RFB 003.008"
			print_good("#{ip}:#{rport} is running a vulnerable RealVNC server")
		else
			print_error("#{ip}:#{rport} is not vulnerable")
		end
	end
end
