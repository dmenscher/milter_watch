#!/usr/bin/perl -w
# 
# University of Illinois/NCSA Open Source License
# 
# Copyright (c) 2005, The Board of Trustees, University of Illinois.
# All rights reserved.
# 
# Developed by:  Damian Menscher <menscher@gmail.com>
#                Imaging Technology Group
#                Beckman Institute for Advanced Science and Technology
#                University of Illinois at Urbana-Champaign
#                http://www.itg.uiuc.edu/
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the Software), to deal
# with the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#   * Redistributions of source code must retain the above copyright notice,
#     this list of conditions and the following disclaimers.
#   * Redistributions in binary form must reproduce the above copyright notice,
#     this list of conditions and the following disclaimers in the documentation
#     and/or other materials provided with the distribution.
#   * Neither the names of Imaging Technology Group, University of Illinois, nor
#     the names of its contributors may be used to endorse or promote products
#     derived from this Software without specific prior written permission.
# 
# THE SOFTWARE IS PROVIDED AS IS, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
# CONTRIBUTORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS WITH
# THE SOFTWARE.
#   
#   ChangeLog
#   v0.6 - 2009.05.03 - invert return code; parse option negotiation; cleanups
#   v0.5 - 2006.04.30 - TCP ports on remote machines; test spam milters too
#   v0.4 - 2005.07.30 - test false positives; add flag to allow viruses through
#   v0.3 - 2005.04.08 - handle stale socket
#   v0.2 - 2005.03.22 - code cleanup and public release
#   v0.1 - 2005.02.21 - initial proof of concept

use Getopt::Std;
use IO::Socket;
use MIME::Base64;
use strict;

# Return codes
use constant EXIT_WORKING => 0;
use constant EXIT_BROKEN  => 1;

sub print_help {
  print("
  Synopsis:
    milter_watch [options] socket_address
    
    socket_address should be given in a standard format:
                   local:/path/to/socket or inet:port\@host
  
  Options:
    -h           This help screen
    -q           Quiet mode (don't print status)
    -d           Debug mode (lots of ugly information)
    -t timeout   Seconds to wait for milter response (default: 15)
    -L lockfile  Path to milter lockfile (abort if file doesn't exist)
    -A           Allow malware through if header added
    -r recipient Email address of recipient (default: victim)
  
  Returns 0 if milter working, or administratively shut down
          1 if milter should be restarted

  Recommended cronjob:
    milter_watch -q local:/var/milter.sock || /etc/init.d/milter condrestart
  ");
  exit EXIT_BROKEN;
}

my %options;
getopts('hqdt:L:Ar:', \%options);

$options{h} && print_help;

# Default values
my $socket    = shift || print_help;
my $quiet     = $options{q} || 0;
my $debug     = $options{d} || 0;
my $timeout   = $options{t} || 15;
my $lockfile  = $options{L} || "/dev/null";
my $allow     = $options{A} || 0;
my $rcpt_addr = $options{r} || 'victim';
my $relayname = 'localhost.localdomain';
my $relay_ip  = '127.0.0.1';
my $message_id = 'milter_watch';
my $infected_host = 'infected.invalid';
my $infected_addr = "malware\@$infected_host";
my $headers;
$headers  = "To: $rcpt_addr\n";
$headers .= "Subject: milter test message\n";
$headers .= "Content-Transfer-Encoding: BASE64\n";
my ($racie, $ebutg, $sock, $status);
$racie = '*H+H$!ELIF-TSET-SURIVITNA-DRADNATS-RACIE$}7)CC7)^P(45XZP\4[PA@%P!O5X';
$ebutg = 'X43.C*LIAME-TSET-EBU-ITNA-DRADNATS-EBUTG*NENDI2*3NBSN.1NDAQBDJ4C*SJX';

$debug && print("D milter_watch-0.6 by Damian Menscher <menscher\@gmail.com>\n");
# Don't test if milter administratively shut down
if (! -e $lockfile) {
  !$quiet && print("F Lockfile missing, milter not tested\n");
  exit EXIT_WORKING;
}

# codes specified in sendmail src: .../include/libmilter/mfdef.h
# Discard, Quarantine, Reject, replY, Tempfail, -recipient
$sock = open_sock($socket, $timeout);
$status = submit_message(encode_base64(        $racie )."\n".        $ebutg );
if ($status !~ "clean") {
  print "W Milter blocked a clean mail!\n";
  exit EXIT_BROKEN;
}
!$quiet && print "I Milter properly allowed clean mail through\n";

$sock = open_sock($socket, $timeout);
$status = submit_message(encode_base64(reverse($racie))."\n".reverse($ebutg));
if (not ($status =~ "infected" or ($allow and $status =~ "header added"))) {
  print "W Milter didn't find the test spam/virus!\n";
  exit EXIT_BROKEN;
}
!$quiet && print "I Milter blocked a spam/virus\n";
exit EXIT_WORKING;

# Utility functions
sub open_sock {
  my ($socket, $timeout) = @_;
  if ( $socket =~ /^local:(\S+)$/i ) {
    $socket = $1;
    $sock = IO::Socket::UNIX->new(Type     => SOCK_STREAM,
                                  Timeout  => $timeout,
                                  Peer     => $socket);
  } elsif ( $socket =~ /^inet:(\d+)@(\S+)$/i ) {
    my $port = $1;
    my $host = $2;
    $sock = IO::Socket::INET->new(PeerAddr => $host,
                                  PeerPort => $port,
                                  Proto    => 'tcp');
  } else {
    printf("F Please give socket in form:  local:/path/to/socket\n");
    printf("                          or:  inet:port\@host\n");
    exit EXIT_BROKEN;
  }
  if (!$sock) {
    printf("F Couldn't open socket %s\n", $socket);
    printf("F Error was: %s\n", $!);
    exit EXIT_BROKEN;
  }
  return $sock
}

sub submit_message {
  $debug && printf("D Submit_message called with \"\"\"\n%s\n\"\"\"\n", $_[0]);
  $SIG{ALRM} = sub {
    printf("E Milter didn't respond within %ds timeout\n", $timeout);
    exit EXIT_BROKEN;
  };
  alarm($timeout); # bail out if timeout is reached
  
  use constant SMFIC_OPTNEG  => "O";
  use constant SMFIC_MACRO   => "D";
  use constant SMFIC_CONNECT => "C";
  use constant SMFIC_HELO    => "H";
  use constant SMFIC_MAIL    => "M";
  use constant SMFIC_RCPT    => "R";
  use constant SMFIC_HEADER  => "L";
  use constant SMFIC_EOH     => "N";
  use constant SMFIC_BODY    => "B";
  use constant SMFIC_BODYEOB => "E";
  use constant SMFIC_QUIT    => "Q";

  use constant SMFIR_CONTINUE => "c";

  use constant NULL => "\x00";

  use constant SMFIA_INET => 4;
  use constant PORT => pack("n", 10000);

  my ($string, $response);
  $string  = SMFIC_OPTNEG;
  $string .= pack("N", 2);    # SMFI_VERSION
  $string .= pack("N", 0x3f); # SMFIF allowed actions
  $string .= pack("N", 0x7f); # SMFIP possible protocol content
  send_string($string);
  my ($cmd, $smfi_ver, $req_actions, $undesired_content) = unpack(
      "CN*", get_response());
  if (chr($cmd) ne SMFIC_OPTNEG) {
    printf("E Expected Option negotiation, got 0x%x\n", $cmd);
  }
  ($smfi_ver != 2) && printf("E Expected SMFI_VERSION=2, got 0x%x\n", $smfi_ver);
  $debug && printf("D Requested actions: 0x%x; Undesired content 0x%x\n",
                   $req_actions, $undesired_content);
  $string  = SMFIC_MACRO;
  $string .= SMFIC_CONNECT;
  $string .= "j".NULL."$relayname".NULL."_".NULL."$relayname [$relay_ip]".NULL;
  $string .= "{daemon_name}".NULL."MTA".NULL;
  $string .= "{if_name}".NULL."$relayname".NULL;
  $string .= "{if_addr}".NULL."$relay_ip".NULL;
  send_string($string);
  $string  = SMFIC_CONNECT;
  $string .= "$relayname".NULL.SMFIA_INET.PORT."$relay_ip".NULL;
  send_string($string);
  get_response();
  $string  = SMFIC_MACRO;
  $string .= SMFIC_HELO;
  send_string($string);
  $string  = SMFIC_MACRO;
  $string .= SMFIC_MAIL;
  $string .= "i".NULL."$message_id".NULL."{mail_mailer}".NULL."esmtp".NULL;
  $string .= "{mail_host}".NULL."$infected_host.".NULL;
  $string .= "{mail_addr}".NULL."$infected_addr".NULL;
  send_string($string);
  $string  = SMFIC_MAIL;
  $string .= "$infected_addr".NULL;
  send_string($string);
  get_response();
  $string  = SMFIC_MACRO;
  $string .= SMFIC_RCPT;
  $string .= "{rcpt_mailer}".NULL."local".NULL;
  $string .= "{rcpt_host}".NULL.NULL."{rcpt_addr}".NULL."$rcpt_addr".NULL;
  send_string($string);
  $string  = SMFIC_RCPT;
  $string .= "$rcpt_addr".NULL;
  send_string($string);
  get_response();
  $string  = SMFIC_EOH;
  send_string($string);
  get_response();
  $string  = SMFIC_BODY;
  $string .= "$headers\n$_[0]\n";
  send_string($string);
  get_response();
  $string  = SMFIC_BODYEOB;
  send_string($string);
  my $status = "clean";
  my $scan_result = get_response();
  while ($scan_result =~ "^[h+]") {	# eat headers or extra recipients
    if ($scan_result =~ "h.*X-Virus-Status.*Infected") {
      $status = "header added";
    }
    $scan_result = get_response();
  }
  alarm(0);	# disable timer; we got a response
  $string  = SMFIC_QUIT;
  send_string($string);
  if ($scan_result =~ "^([dqryt]|-$rcpt_addr)") {
    $status = "infected";
  }
  return $status;
}

sub send_string {
  $debug && printf("D Sending: %s\n", $_[0]);
  $sock->print(pack('N',length($_[0])), $_[0]);
}

sub get_response {
  my $bytesNeeded = 4;
  my $content = '';
  my $newBytes;
  while ($bytesNeeded > 0) {
    $sock->recv($newBytes, $bytesNeeded);
    $content .= $newBytes;
    $bytesNeeded -= length($newBytes);
  }
  $debug && printf("D Milter returned 0x%x bytes: ", unpack('N', $content));
  $bytesNeeded = unpack('N', $content);
  $content = '';
  while ($bytesNeeded > 0) {
    $sock->recv($newBytes, $bytesNeeded);
    $content .= $newBytes;
    $bytesNeeded -= length($newBytes);
  }
  $debug && printf("%s\n", $content);
  return $content;
}
