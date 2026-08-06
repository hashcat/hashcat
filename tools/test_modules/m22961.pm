#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use File::Spec;
use File::Temp qw(tempdir);
use MIME::Base64 qw(encode_base64 decode_base64);

sub module_constraints { [[1, 256], [-1, -1], [-1, -1], [-1, -1], [-1, -1]] }

BEGIN
{
  if (defined &pack_if_HEX_notation == 0)
  {
    *pack_if_HEX_notation = sub
    {
      my $string = shift;

      return unless defined $string;

      if ($string =~ /^\$HEX\[[0-9a-fA-F]*\]$/)
      {
        return pack ("H*", substr ($string, 5, -1));
      }

      return $string;
    };
  }
}

sub read_u32_be
{
  my $buf = shift;
  my $off = shift;

  return unpack ("N", substr ($buf, $off, 4));
}

sub read_ssh_string
{
  my $buf = shift;
  my $off = shift;

  return if ($off + 4 > length ($buf));

  my $len = read_u32_be ($buf, $off);

  $off += 4;

  return if ($off + $len > length ($buf));

  my $str = substr ($buf, $off, $len);

  $off += $len;

  return ($str, $off);
}

sub openssh_key_to_hash
{
  my $data = shift;

  my $magic = "openssh-key-v1\0";

  return unless substr ($data, 0, length ($magic)) eq $magic;

  my $offset = length ($magic);

  my ($ciphername, $off1) = read_ssh_string ($data, $offset);
  return unless defined $ciphername;

  my ($kdfname, $off2) = read_ssh_string ($data, $off1);
  return unless defined $kdfname;

  my ($kdfopts, $off3) = read_ssh_string ($data, $off2);
  return unless defined $kdfopts;

  return unless $ciphername eq "aes256-ctr";
  return unless $kdfname eq "bcrypt";
  return unless length ($kdfopts) == 24;

  my $salt_len = read_u32_be ($kdfopts, 0);
  my $salt     = substr ($kdfopts, 4, $salt_len);
  my $rounds   = read_u32_be ($kdfopts, 4 + $salt_len);

  return unless $salt_len == 16;
  return unless defined $rounds;
  return unless $rounds > 0;

  $offset = $off3;

  return if ($offset + 4 > length ($data));

  my $nr_keys = read_u32_be ($data, $offset);

  $offset += 4;

  return unless $nr_keys >= 1;

  for (my $i = 0; $i < $nr_keys; $i++)
  {
    my ($pubkey, $next_offset) = read_ssh_string ($data, $offset);

    return unless defined $pubkey;

    $offset = $next_offset;
  }

  return if ($offset + 4 > length ($data));

  my $priv_len = read_u32_be ($data, $offset);

  $offset += 4;

  return if (($priv_len & 15) != 0);
  return if ($offset + $priv_len != length ($data));

  my $cipher_offset = $offset;

  return sprintf ('$sshng$6$%d$%s$%d$%s$%d$%d',
    $salt_len,
    unpack ("H*", $salt),
    length ($data),
    unpack ("H*", $data),
    $rounds,
    $cipher_offset);
}

sub read_openssh_private_key
{
  my $path = shift;

  open (my $fh, '<', $path) or die "$path: $!\n";

  local $/ = undef;

  my $pem = <$fh>;

  close ($fh);

  $pem =~ s/\r//g;
  $pem =~ s/-----BEGIN OPENSSH PRIVATE KEY-----//g;
  $pem =~ s/-----END OPENSSH PRIVATE KEY-----//g;
  $pem =~ s/\s+//g;

  return decode_base64 ($pem);
}

sub write_openssh_private_key
{
  my $path = shift;
  my $data = shift;

  my $pem = "-----BEGIN OPENSSH PRIVATE KEY-----\n";

  $pem .= encode_base64 ($data);
  $pem .= "-----END OPENSSH PRIVATE KEY-----\n";

  open (my $fh, '>', $path) or die "$path: $!\n";

  print $fh $pem;

  close ($fh);

  chmod 0600, $path;
}

sub module_generate_hash
{
  my $word   = shift;
  my $salt   = shift;
  my $rounds = shift // 4;

  my $tmpdir = tempdir (CLEANUP => 1);
  my $key    = File::Spec->catfile ($tmpdir, 'id_ed25519');

  my $rc = system ('ssh-keygen', '-q', '-t', 'ed25519', '-N', $word, '-C', '', '-f', $key, '-a', $rounds, '-Z', 'aes256-ctr');

  die "ssh-keygen failed\n" if $rc != 0;

  my $data = read_openssh_private_key ($key);
  my $hash = openssh_key_to_hash ($data);

  die "failed to convert OpenSSH key to hash\n" unless defined $hash;

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my $idx = index ($line, ':');

  return unless $idx >= 0;

  my $hash = substr ($line, 0, $idx);
  my $word = substr ($line, $idx + 1);

  return unless $hash =~ /^\$sshng\$6\$(\d+)\$([0-9a-fA-F]+)\$(\d+)\$([0-9a-fA-F]+)\$(\d+)\$(\d+)$/;

  my $data_len = $3;
  my $data_hex = $4;

  return unless $data_len * 2 == length ($data_hex);

  my $word_packed = pack_if_HEX_notation ($word);
  my $data        = pack ("H*", $data_hex);

  my $tmpdir = tempdir (CLEANUP => 1);
  my $key    = File::Spec->catfile ($tmpdir, 'id_ed25519');

  write_openssh_private_key ($key, $data);

  open (my $saved_out, '>&', \*STDOUT) or die $!;
  open (my $saved_err, '>&', \*STDERR) or die $!;
  open (STDOUT, '>', File::Spec->devnull ()) or die $!;
  open (STDERR, '>', File::Spec->devnull ()) or die $!;

  my $rc = system ('ssh-keygen', '-y', '-P', $word_packed, '-f', $key);

  open (STDOUT, '>&', $saved_out) or die $!;
  open (STDERR, '>&', $saved_err) or die $!;

  return unless $rc == 0;

  return ($hash, $word);
}

1;
