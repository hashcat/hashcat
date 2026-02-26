##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::SHA qw (sha256);
use Crypt::Digest::RIPEMD160 qw (ripemd160_hex);

sub module_constraints { [[0, 256], [0, 256], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;

  my $digest = ripemd160_hex (sha256 ($salt . sha256 ($word)));

  my $hash = sprintf ("%s:%s", $digest, unpack ("H*", $salt));

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($hash, $salt, $word) = split (':', $line);

  return unless defined $hash;
  return unless defined $salt;
  return unless defined $word;

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt);

  return ($new_hash, $word_packed);
}

1;
