#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::CBC;
use Crypt::DES_EDE3;
use Digest::MD5 qw (md5);

sub module_constraints { [[0, 256], [16, 16], [-1, -1], [-1, -1], [-1, -1]] }

sub generate_key
{
  my $word  = shift;
  my $salt  = shift;
  my $bytes = shift;

  my $salt8 = substr ($salt, 0, 8);

  my $out = md5 ($word . $salt8);

  $out .= md5 ($out . $word . $salt8);

  return substr ($out, 0, 24);
}

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;
  my $cid  = shift // 0;
  my $data = shift;

  my $salt_bin = pack ("H*", $salt);
  my $data_bin;

  my $key = generate_key ($word, $salt_bin);

  my $is_decrypt = defined ($data);

  if ($is_decrypt == 1)
  {
    $data_bin = pack ("H*", $data);

    my $aes = Crypt::CBC->new ({
      cipher      => "Crypt::DES_EDE3",
      key         => $key,
      iv          => $salt_bin,
      keysize     => 24,
      literal_key => 1,
      header      => "none",
      padding     => "standard",
    });

    my $dec_bin = $aes->decrypt ($data_bin);

    ## This is a ridiculous check of successfull decryption
    ## There are no useable asn1 parsers for perl available
    ## We have to rely on a combination of padding check and pattern matching
    ## The (minimum) 16 bit should be good enough for a unit test

    if (length ($dec_bin) < length ($data_bin))
    {
      if (substr ($dec_bin, 0, 1) eq "\x30")
      {
        $data_bin = $dec_bin;
      }
    }
  }
  else
  {
    $data_bin = pack ("H*",
      "308204bd020100300d06092a864886f70d0101010500048204a7308204a30201000282010100b7a2" .
      "e4c254c8174219e60d9cce96737a906797b8edb86af8f055f60db7bd298b0d31d7ce97ebeae393d5" .
      "0e6da5215b58dcd72f4d3cac9e79b6ccaed7da47d2bd04f6a767f5ab7dc0f58beb6298c1e2358ed6" .
      "d3ef441f2326ac5db0027e08ae6c7724ff9a2a220a07e97319b6eff5cd653c7ab8b6ea9f9e89a40a" .
      "b856f036acfd39b1e5926964a024de35052de6d3423fe763569f48869c834750b28f09cecdddb54a" .
      "5526a2c5159d22d24606a2af6c6f47a5d9c04c454896192b8e7b82cf6f6934a23d3495059cb7e43b" .
      "98a20bd5b5782e15d93c8b289838c0a1df82ee429f0708d97aa40d6e75ec57ff12a2714871f241a8" .
      "6f6d8d3472b084aeb748da33e2d50203010001028201004afab8dadc1122e5fb7b225dbf4051005f" .
      "4bdcf84620019589541ff633ea89b6dbf958fb62ae9226bfeac34c639b3e18077bd935792ba63d5e" .
      "352ec2b5be93be57f37a21097f2f06857bceed601ff2041a417f2177b81afb246fd079040af96512" .
      "34ca24a1456ac11641c7e319114cff23f59bcc1bfa769a0e9fcdeab98429973e10caf303f2bcb065" .
      "f22c1cc259556de8377431237da7082cf03ce8da9530be398022f0171d468d92fcabbe776a5e9cf2" .
      "045642868406fd03ab735a70bfec3a951bb3c7a1de0fb3ff63cef23897e4fc3f9c5edf62fd45d058" .
      "fedc7d2fb22ec928984a061053a7138ce0417b5512579a92be0775104c0bc911f68a5e8ede298102" .
      "818100e4e17e2c752dbf1ad1025a074dc5f9c3c5989d23c84594313373d3e4ed0c0ddd74429ab026" .
      "535c5e77549d888835bc94f069ebc5e77fdbd2ddf4c8be6cf777799a6d8d18e2b8cecfc13ab26df8" .
      "b71ca3d94c2193c294042fb1025fdab38ba7aaeafebd8dd1f9d78ee67100693e99255dad6b964ebf" .
      "b7401a03b67d412fabb33502818100cd65067097e307643df1fc8214db1dd7d09342ef01417a2620" .
      "adad87352a58b8fcf07521289da3851623d8d045935fab7ecccc52ba0b86adcb92da76255e00289b" .
      "af9aacd936201861b0021249f4ab5e6020db823af7171aef0bbbd02dc94d2489fc0b68500bd1b7d2" .
      "81ed69fe4a44384161fe906e49bc91e0362b446ec2c521028180497662d40c2c49b966ba758100a2" .
      "799f2f8de369f7bef568b1560cfdde63cf13745c685fff7d2419a1fd83aeade1698cf87956d6a78e" .
      "2f55482e683c4ea7432ec1b545e365e9e15f676ada98578b166334bcadce4a56cddd2cd85141d5fd" .
      "0e2cdace36b30d613ea1bc2f2aed9cccf4e4536443d334cfb180680eabb73f80c1bd0281803f30fc" .
      "b93951a4dd875d62e5968b0f746d7c51147d5b6abc3e4390e6cf4997005af993dfbec23923e1fae7" .
      "62b47531f2ee510defc9c3700d1a5bb510b2506856160801db79fc78056850a16285145c80edac4e" .
      "3c93ed9f532f067a2303633273b26c340a44ce4e1873107c3da6f9ac616e643ad0aecdcad14a9cff" .
      "d4cf0ae76102818100b82528a3dfc595cf9c6a025998491e3b4849c71aa8d1222ddb14af7f82fbe5" .
      "169ec3ba18ec28d5a9501e95bc9da72cea99e4cdfdf898f40bec6b28f838243d2f39d7226e0873ed" .
      "ee752bcae07639a4bd0eb31be1718c456391630b83ad0e9bf3fa18a645007e64fe59af467ea021f9" .
      "e9a0dd759b21cd0b93333a73116abcaa2a"
     );
  }

  my $aes = Crypt::CBC->new ({
    cipher      => "Crypt::DES_EDE3",
    key         => $key,
    iv          => $salt_bin,
    keysize     => 24,
    literal_key => 1,
    header      => "none",
    padding     => "standard",
  });

  my $enc_bin = $aes->encrypt ($data_bin);

  my $hash = sprintf ('$sshng$%d$%d$%s$%d$%s', $cid, length ($salt_bin), unpack ("H*", $salt_bin), length ($enc_bin), unpack ("H*", $enc_bin));

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my $idx = index ($line, ':');

  return unless $idx >= 0;

  my $hash = substr ($line, 0, $idx);
  my $word = substr ($line, $idx + 1);

  return unless substr ($hash, 0, 7) eq '$sshng$';

  my (undef, $signature, $cid, undef, $salt, undef, $data) = split '\$', $hash;

  return unless defined $signature;
  return unless defined $cid;
  return unless defined $salt;
  return unless defined $data;

  return unless ($signature eq 'sshng');

  return unless ($cid == 0);

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt, $cid, $data);

  return ($new_hash, $word);
}

1;
