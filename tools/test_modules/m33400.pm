#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Convert::EBCDIC qw (ascii2ebcdic);
use Digest::HMAC qw (hmac);
use Digest::SHA qw(hmac_sha256);
use Crypt::PBKDF2;
use Crypt::DES;
use Crypt::Rijndael;

sub module_constraints { [[0, 8], [1, 8], [-1, -1], [-1, -1], [-1, -1]] }

sub prepare_hmac_key
{
  my ($username, $password) = @_;

  $username = substr ($username . " " x 8, 0, 8);
  $password = substr ($password . " " x 8, 0, 8);

  my $username_ebc = ascii2ebcdic ($username);
  my $password_ebc = ascii2ebcdic ($password);

  my @pw = split ("", $password_ebc); # split by char

  for (my $i = 0; $i < 8; $i++)
  {
    $pw[$i] = unpack ("C", $pw[$i]);
    $pw[$i] ^= 0x55;
    $pw[$i] <<= 1;
    $pw[$i] = pack ("C", $pw[$i] & 0xff);
  }

  my $key = join ("", @pw);

  my $cipher = new Crypt::DES $key;

  my $ciphertext = $cipher->encrypt ($username_ebc);

  return $ciphertext;
}

sub prepare_aes_key
{
	my $mem_fac = (2 << (shift() - 1)) / 32; 
	my $rep_fac = shift;
	my $hmac_key = shift;
	my $data_hex = shift;

	my $msg = pack ("H32", $data_hex) . pack('N', $mem_fac) . pack('N', 1);
	my $mem_buf = "";

	# step 1: proprietary PBKDF2-HMAC-SHA256 (prepare $mem_buf)
	
	for my $n (0 .. $mem_fac - 1) {
	
		my $u_current = hmac_sha256($msg, $hmac_key);
		my $f_res = $u_current;
		my $h_prev = $u_current;

		# recalc hmac
		for my $i (0 .. $rep_fac * 100 - 2) {
			$h_prev = $u_current;
			$u_current = hmac_sha256($u_current, $hmac_key);
  	  my $f_res_tmp = '';
			for my $j (0 .. length($f_res) - 1) {
			    $f_res_tmp .= chr(ord(substr($f_res, $j, 1)) ^ ord(substr($u_current, $j, 1)));
			}
			$f_res = $f_res_tmp;
		}

		$msg = substr ($h_prev, 0, 16) . $f_res . pack('N', 1);
		$mem_buf .= $f_res
	}

	
	# step 2: mem_buf substitutions

	# Set new HMAC key (last block from mem_buf)
	my $mem_buf_len = length ($mem_buf);
	$hmac_key = substr ($mem_buf, $mem_buf_len - 32, 32);
	
	# Substitutions
	for my $n (0 .. $mem_fac - 1) {
		my $n_key = unpack ('N', substr ($hmac_key, 28, 4) ) & ($mem_fac - 1);
		my $mem_buf_blk = substr ($mem_buf, $n_key * 32, 32) . pack('N', 1);
		
		$mem_buf_blk = hmac_sha256($mem_buf_blk, $hmac_key);
		$mem_buf = substr ($mem_buf, 0, $n * 32) . $mem_buf_blk . substr ($mem_buf, ($n+1) * 32, $mem_buf_len - ($n+1) * 32);
		$hmac_key = $mem_buf_blk;
	}

	# step 3: PBKDF2-HMAC-SHA256(mem_buf, hmac_key, rep_fac)

	my $pbkdf2 = Crypt::PBKDF2->new
  (
    hasher     => Crypt::PBKDF2->hasher_from_algorithm ('HMACSHA2', 256),
    iterations => $rep_fac*100,
    output_len => 32
  );
  $msg = substr ($mem_buf, 0, ($mem_fac-1) * 32);
  my $aes_key = $pbkdf2->PBKDF2 ($msg, $hmac_key);

  return $aes_key; 	
}

sub module_generate_hash
{
  my $word = shift;
  my $username = shift;

  my $mem_fac = shift // 0x08;
  my $rep_fac = shift // 0x32;
  my $salt_data = shift // uc random_hex_string (32);

  my $hmac_key = prepare_hmac_key (uc $username, $word);
  
  my $aes_key = prepare_aes_key ($mem_fac, $rep_fac, $hmac_key, $salt_data);
  
  my $plaint = ascii2ebcdic (substr (uc $username . " " x 8, 0, 8)) . "\x00" x 8;
  my $rijndael = Crypt::Rijndael->new($aes_key, Crypt::Rijndael::MODE_ECB());
	my $ciphertext = $rijndael->encrypt($plaint);

  my $hash = sprintf ('$racf-kdfaes$*%s*E7D7E66D00018000%04X%04X00100010*%s*%s', uc $username, $mem_fac, $rep_fac, uc $salt_data, uc unpack("H32", $ciphertext));

  return $hash;
}


sub module_verify_hash
{
  my $line = shift;

  my @line_elements = split (":", $line);

  return if scalar @line_elements < 2;

  my $hash_in = shift @line_elements;

  my $word = join (":", @line_elements);

  # check signature

  my @hash_elements = split ('\*', $hash_in);

  return unless ($hash_elements[0] eq '$racf-kdfaes$');

  my $username = $hash_elements[1];
  my $mem_fac = hex (substr ($hash_elements[2], 16, 4));
  my $rep_fac = hex (substr ($hash_elements[2], 20, 4));
  my $salt = $hash_elements[3];

  return unless defined $word;
  return unless defined $username;
  return unless defined $mem_fac;
  return unless defined $rep_fac;
  return unless defined $salt;

  $word = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word, $username, $mem_fac, $rep_fac, $salt);

  return ($new_hash, $word);
}

1;



