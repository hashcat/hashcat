#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;
use Math::BigInt;

sub module_constraints { [[-1, -1], [-1, -1], [0, 31], [16, 16], [-1, -1]] }

my @tbl =
(
  Math::BigInt->new ("0x" . "0000000000000000"), Math::BigInt->new ("0x" . "7ad870c830358979"),
  Math::BigInt->new ("0x" . "f5b0e190606b12f2"), Math::BigInt->new ("0x" . "8f689158505e9b8b"),
  Math::BigInt->new ("0x" . "c038e5739841b68f"), Math::BigInt->new ("0x" . "bae095bba8743ff6"),
  Math::BigInt->new ("0x" . "358804e3f82aa47d"), Math::BigInt->new ("0x" . "4f50742bc81f2d04"),
  Math::BigInt->new ("0x" . "ab28ecb46814fe75"), Math::BigInt->new ("0x" . "d1f09c7c5821770c"),
  Math::BigInt->new ("0x" . "5e980d24087fec87"), Math::BigInt->new ("0x" . "24407dec384a65fe"),
  Math::BigInt->new ("0x" . "6b1009c7f05548fa"), Math::BigInt->new ("0x" . "11c8790fc060c183"),
  Math::BigInt->new ("0x" . "9ea0e857903e5a08"), Math::BigInt->new ("0x" . "e478989fa00bd371"),
  Math::BigInt->new ("0x" . "7d08ff3b88be6f81"), Math::BigInt->new ("0x" . "07d08ff3b88be6f8"),
  Math::BigInt->new ("0x" . "88b81eabe8d57d73"), Math::BigInt->new ("0x" . "f2606e63d8e0f40a"),
  Math::BigInt->new ("0x" . "bd301a4810ffd90e"), Math::BigInt->new ("0x" . "c7e86a8020ca5077"),
  Math::BigInt->new ("0x" . "4880fbd87094cbfc"), Math::BigInt->new ("0x" . "32588b1040a14285"),
  Math::BigInt->new ("0x" . "d620138fe0aa91f4"), Math::BigInt->new ("0x" . "acf86347d09f188d"),
  Math::BigInt->new ("0x" . "2390f21f80c18306"), Math::BigInt->new ("0x" . "594882d7b0f40a7f"),
  Math::BigInt->new ("0x" . "1618f6fc78eb277b"), Math::BigInt->new ("0x" . "6cc0863448deae02"),
  Math::BigInt->new ("0x" . "e3a8176c18803589"), Math::BigInt->new ("0x" . "997067a428b5bcf0"),
  Math::BigInt->new ("0x" . "fa11fe77117cdf02"), Math::BigInt->new ("0x" . "80c98ebf2149567b"),
  Math::BigInt->new ("0x" . "0fa11fe77117cdf0"), Math::BigInt->new ("0x" . "75796f2f41224489"),
  Math::BigInt->new ("0x" . "3a291b04893d698d"), Math::BigInt->new ("0x" . "40f16bccb908e0f4"),
  Math::BigInt->new ("0x" . "cf99fa94e9567b7f"), Math::BigInt->new ("0x" . "b5418a5cd963f206"),
  Math::BigInt->new ("0x" . "513912c379682177"), Math::BigInt->new ("0x" . "2be1620b495da80e"),
  Math::BigInt->new ("0x" . "a489f35319033385"), Math::BigInt->new ("0x" . "de51839b2936bafc"),
  Math::BigInt->new ("0x" . "9101f7b0e12997f8"), Math::BigInt->new ("0x" . "ebd98778d11c1e81"),
  Math::BigInt->new ("0x" . "64b116208142850a"), Math::BigInt->new ("0x" . "1e6966e8b1770c73"),
  Math::BigInt->new ("0x" . "8719014c99c2b083"), Math::BigInt->new ("0x" . "fdc17184a9f739fa"),
  Math::BigInt->new ("0x" . "72a9e0dcf9a9a271"), Math::BigInt->new ("0x" . "08719014c99c2b08"),
  Math::BigInt->new ("0x" . "4721e43f0183060c"), Math::BigInt->new ("0x" . "3df994f731b68f75"),
  Math::BigInt->new ("0x" . "b29105af61e814fe"), Math::BigInt->new ("0x" . "c849756751dd9d87"),
  Math::BigInt->new ("0x" . "2c31edf8f1d64ef6"), Math::BigInt->new ("0x" . "56e99d30c1e3c78f"),
  Math::BigInt->new ("0x" . "d9810c6891bd5c04"), Math::BigInt->new ("0x" . "a3597ca0a188d57d"),
  Math::BigInt->new ("0x" . "ec09088b6997f879"), Math::BigInt->new ("0x" . "96d1784359a27100"),
  Math::BigInt->new ("0x" . "19b9e91b09fcea8b"), Math::BigInt->new ("0x" . "636199d339c963f2"),
  Math::BigInt->new ("0x" . "df7adabd7a6e2d6f"), Math::BigInt->new ("0x" . "a5a2aa754a5ba416"),
  Math::BigInt->new ("0x" . "2aca3b2d1a053f9d"), Math::BigInt->new ("0x" . "50124be52a30b6e4"),
  Math::BigInt->new ("0x" . "1f423fcee22f9be0"), Math::BigInt->new ("0x" . "659a4f06d21a1299"),
  Math::BigInt->new ("0x" . "eaf2de5e82448912"), Math::BigInt->new ("0x" . "902aae96b271006b"),
  Math::BigInt->new ("0x" . "74523609127ad31a"), Math::BigInt->new ("0x" . "0e8a46c1224f5a63"),
  Math::BigInt->new ("0x" . "81e2d7997211c1e8"), Math::BigInt->new ("0x" . "fb3aa75142244891"),
  Math::BigInt->new ("0x" . "b46ad37a8a3b6595"), Math::BigInt->new ("0x" . "ceb2a3b2ba0eecec"),
  Math::BigInt->new ("0x" . "41da32eaea507767"), Math::BigInt->new ("0x" . "3b024222da65fe1e"),
  Math::BigInt->new ("0x" . "a2722586f2d042ee"), Math::BigInt->new ("0x" . "d8aa554ec2e5cb97"),
  Math::BigInt->new ("0x" . "57c2c41692bb501c"), Math::BigInt->new ("0x" . "2d1ab4dea28ed965"),
  Math::BigInt->new ("0x" . "624ac0f56a91f461"), Math::BigInt->new ("0x" . "1892b03d5aa47d18"),
  Math::BigInt->new ("0x" . "97fa21650afae693"), Math::BigInt->new ("0x" . "ed2251ad3acf6fea"),
  Math::BigInt->new ("0x" . "095ac9329ac4bc9b"), Math::BigInt->new ("0x" . "7382b9faaaf135e2"),
  Math::BigInt->new ("0x" . "fcea28a2faafae69"), Math::BigInt->new ("0x" . "8632586aca9a2710"),
  Math::BigInt->new ("0x" . "c9622c4102850a14"), Math::BigInt->new ("0x" . "b3ba5c8932b0836d"),
  Math::BigInt->new ("0x" . "3cd2cdd162ee18e6"), Math::BigInt->new ("0x" . "460abd1952db919f"),
  Math::BigInt->new ("0x" . "256b24ca6b12f26d"), Math::BigInt->new ("0x" . "5fb354025b277b14"),
  Math::BigInt->new ("0x" . "d0dbc55a0b79e09f"), Math::BigInt->new ("0x" . "aa03b5923b4c69e6"),
  Math::BigInt->new ("0x" . "e553c1b9f35344e2"), Math::BigInt->new ("0x" . "9f8bb171c366cd9b"),
  Math::BigInt->new ("0x" . "10e3202993385610"), Math::BigInt->new ("0x" . "6a3b50e1a30ddf69"),
  Math::BigInt->new ("0x" . "8e43c87e03060c18"), Math::BigInt->new ("0x" . "f49bb8b633338561"),
  Math::BigInt->new ("0x" . "7bf329ee636d1eea"), Math::BigInt->new ("0x" . "012b592653589793"),
  Math::BigInt->new ("0x" . "4e7b2d0d9b47ba97"), Math::BigInt->new ("0x" . "34a35dc5ab7233ee"),
  Math::BigInt->new ("0x" . "bbcbcc9dfb2ca865"), Math::BigInt->new ("0x" . "c113bc55cb19211c"),
  Math::BigInt->new ("0x" . "5863dbf1e3ac9dec"), Math::BigInt->new ("0x" . "22bbab39d3991495"),
  Math::BigInt->new ("0x" . "add33a6183c78f1e"), Math::BigInt->new ("0x" . "d70b4aa9b3f20667"),
  Math::BigInt->new ("0x" . "985b3e827bed2b63"), Math::BigInt->new ("0x" . "e2834e4a4bd8a21a"),
  Math::BigInt->new ("0x" . "6debdf121b863991"), Math::BigInt->new ("0x" . "1733afda2bb3b0e8"),
  Math::BigInt->new ("0x" . "f34b37458bb86399"), Math::BigInt->new ("0x" . "8993478dbb8deae0"),
  Math::BigInt->new ("0x" . "06fbd6d5ebd3716b"), Math::BigInt->new ("0x" . "7c23a61ddbe6f812"),
  Math::BigInt->new ("0x" . "3373d23613f9d516"), Math::BigInt->new ("0x" . "49aba2fe23cc5c6f"),
  Math::BigInt->new ("0x" . "c6c333a67392c7e4"), Math::BigInt->new ("0x" . "bc1b436e43a74e9d"),
  Math::BigInt->new ("0x" . "95ac9329ac4bc9b5"), Math::BigInt->new ("0x" . "ef74e3e19c7e40cc"),
  Math::BigInt->new ("0x" . "601c72b9cc20db47"), Math::BigInt->new ("0x" . "1ac40271fc15523e"),
  Math::BigInt->new ("0x" . "5594765a340a7f3a"), Math::BigInt->new ("0x" . "2f4c0692043ff643"),
  Math::BigInt->new ("0x" . "a02497ca54616dc8"), Math::BigInt->new ("0x" . "dafce7026454e4b1"),
  Math::BigInt->new ("0x" . "3e847f9dc45f37c0"), Math::BigInt->new ("0x" . "445c0f55f46abeb9"),
  Math::BigInt->new ("0x" . "cb349e0da4342532"), Math::BigInt->new ("0x" . "b1eceec59401ac4b"),
  Math::BigInt->new ("0x" . "febc9aee5c1e814f"), Math::BigInt->new ("0x" . "8464ea266c2b0836"),
  Math::BigInt->new ("0x" . "0b0c7b7e3c7593bd"), Math::BigInt->new ("0x" . "71d40bb60c401ac4"),
  Math::BigInt->new ("0x" . "e8a46c1224f5a634"), Math::BigInt->new ("0x" . "927c1cda14c02f4d"),
  Math::BigInt->new ("0x" . "1d148d82449eb4c6"), Math::BigInt->new ("0x" . "67ccfd4a74ab3dbf"),
  Math::BigInt->new ("0x" . "289c8961bcb410bb"), Math::BigInt->new ("0x" . "5244f9a98c8199c2"),
  Math::BigInt->new ("0x" . "dd2c68f1dcdf0249"), Math::BigInt->new ("0x" . "a7f41839ecea8b30"),
  Math::BigInt->new ("0x" . "438c80a64ce15841"), Math::BigInt->new ("0x" . "3954f06e7cd4d138"),
  Math::BigInt->new ("0x" . "b63c61362c8a4ab3"), Math::BigInt->new ("0x" . "cce411fe1cbfc3ca"),
  Math::BigInt->new ("0x" . "83b465d5d4a0eece"), Math::BigInt->new ("0x" . "f96c151de49567b7"),
  Math::BigInt->new ("0x" . "76048445b4cbfc3c"), Math::BigInt->new ("0x" . "0cdcf48d84fe7545"),
  Math::BigInt->new ("0x" . "6fbd6d5ebd3716b7"), Math::BigInt->new ("0x" . "15651d968d029fce"),
  Math::BigInt->new ("0x" . "9a0d8ccedd5c0445"), Math::BigInt->new ("0x" . "e0d5fc06ed698d3c"),
  Math::BigInt->new ("0x" . "af85882d2576a038"), Math::BigInt->new ("0x" . "d55df8e515432941"),
  Math::BigInt->new ("0x" . "5a3569bd451db2ca"), Math::BigInt->new ("0x" . "20ed197575283bb3"),
  Math::BigInt->new ("0x" . "c49581ead523e8c2"), Math::BigInt->new ("0x" . "be4df122e51661bb"),
  Math::BigInt->new ("0x" . "3125607ab548fa30"), Math::BigInt->new ("0x" . "4bfd10b2857d7349"),
  Math::BigInt->new ("0x" . "04ad64994d625e4d"), Math::BigInt->new ("0x" . "7e7514517d57d734"),
  Math::BigInt->new ("0x" . "f11d85092d094cbf"), Math::BigInt->new ("0x" . "8bc5f5c11d3cc5c6"),
  Math::BigInt->new ("0x" . "12b5926535897936"), Math::BigInt->new ("0x" . "686de2ad05bcf04f"),
  Math::BigInt->new ("0x" . "e70573f555e26bc4"), Math::BigInt->new ("0x" . "9ddd033d65d7e2bd"),
  Math::BigInt->new ("0x" . "d28d7716adc8cfb9"), Math::BigInt->new ("0x" . "a85507de9dfd46c0"),
  Math::BigInt->new ("0x" . "273d9686cda3dd4b"), Math::BigInt->new ("0x" . "5de5e64efd965432"),
  Math::BigInt->new ("0x" . "b99d7ed15d9d8743"), Math::BigInt->new ("0x" . "c3450e196da80e3a"),
  Math::BigInt->new ("0x" . "4c2d9f413df695b1"), Math::BigInt->new ("0x" . "36f5ef890dc31cc8"),
  Math::BigInt->new ("0x" . "79a59ba2c5dc31cc"), Math::BigInt->new ("0x" . "037deb6af5e9b8b5"),
  Math::BigInt->new ("0x" . "8c157a32a5b7233e"), Math::BigInt->new ("0x" . "f6cd0afa9582aa47"),
  Math::BigInt->new ("0x" . "4ad64994d625e4da"), Math::BigInt->new ("0x" . "300e395ce6106da3"),
  Math::BigInt->new ("0x" . "bf66a804b64ef628"), Math::BigInt->new ("0x" . "c5bed8cc867b7f51"),
  Math::BigInt->new ("0x" . "8aeeace74e645255"), Math::BigInt->new ("0x" . "f036dc2f7e51db2c"),
  Math::BigInt->new ("0x" . "7f5e4d772e0f40a7"), Math::BigInt->new ("0x" . "05863dbf1e3ac9de"),
  Math::BigInt->new ("0x" . "e1fea520be311aaf"), Math::BigInt->new ("0x" . "9b26d5e88e0493d6"),
  Math::BigInt->new ("0x" . "144e44b0de5a085d"), Math::BigInt->new ("0x" . "6e963478ee6f8124"),
  Math::BigInt->new ("0x" . "21c640532670ac20"), Math::BigInt->new ("0x" . "5b1e309b16452559"),
  Math::BigInt->new ("0x" . "d476a1c3461bbed2"), Math::BigInt->new ("0x" . "aeaed10b762e37ab"),
  Math::BigInt->new ("0x" . "37deb6af5e9b8b5b"), Math::BigInt->new ("0x" . "4d06c6676eae0222"),
  Math::BigInt->new ("0x" . "c26e573f3ef099a9"), Math::BigInt->new ("0x" . "b8b627f70ec510d0"),
  Math::BigInt->new ("0x" . "f7e653dcc6da3dd4"), Math::BigInt->new ("0x" . "8d3e2314f6efb4ad"),
  Math::BigInt->new ("0x" . "0256b24ca6b12f26"), Math::BigInt->new ("0x" . "788ec2849684a65f"),
  Math::BigInt->new ("0x" . "9cf65a1b368f752e"), Math::BigInt->new ("0x" . "e62e2ad306bafc57"),
  Math::BigInt->new ("0x" . "6946bb8b56e467dc"), Math::BigInt->new ("0x" . "139ecb4366d1eea5"),
  Math::BigInt->new ("0x" . "5ccebf68aecec3a1"), Math::BigInt->new ("0x" . "2616cfa09efb4ad8"),
  Math::BigInt->new ("0x" . "a97e5ef8cea5d153"), Math::BigInt->new ("0x" . "d3a62e30fe90582a"),
  Math::BigInt->new ("0x" . "b0c7b7e3c7593bd8"), Math::BigInt->new ("0x" . "ca1fc72bf76cb2a1"),
  Math::BigInt->new ("0x" . "45775673a732292a"), Math::BigInt->new ("0x" . "3faf26bb9707a053"),
  Math::BigInt->new ("0x" . "70ff52905f188d57"), Math::BigInt->new ("0x" . "0a2722586f2d042e"),
  Math::BigInt->new ("0x" . "854fb3003f739fa5"), Math::BigInt->new ("0x" . "ff97c3c80f4616dc"),
  Math::BigInt->new ("0x" . "1bef5b57af4dc5ad"), Math::BigInt->new ("0x" . "61372b9f9f784cd4"),
  Math::BigInt->new ("0x" . "ee5fbac7cf26d75f"), Math::BigInt->new ("0x" . "9487ca0fff135e26"),
  Math::BigInt->new ("0x" . "dbd7be24370c7322"), Math::BigInt->new ("0x" . "a10fceec0739fa5b"),
  Math::BigInt->new ("0x" . "2e675fb4576761d0"), Math::BigInt->new ("0x" . "54bf2f7c6752e8a9"),
  Math::BigInt->new ("0x" . "cdcf48d84fe75459"), Math::BigInt->new ("0x" . "b71738107fd2dd20"),
  Math::BigInt->new ("0x" . "387fa9482f8c46ab"), Math::BigInt->new ("0x" . "42a7d9801fb9cfd2"),
  Math::BigInt->new ("0x" . "0df7adabd7a6e2d6"), Math::BigInt->new ("0x" . "772fdd63e7936baf"),
  Math::BigInt->new ("0x" . "f8474c3bb7cdf024"), Math::BigInt->new ("0x" . "829f3cf387f8795d"),
  Math::BigInt->new ("0x" . "66e7a46c27f3aa2c"), Math::BigInt->new ("0x" . "1c3fd4a417c62355"),
  Math::BigInt->new ("0x" . "935745fc4798b8de"), Math::BigInt->new ("0x" . "e98f353477ad31a7"),
  Math::BigInt->new ("0x" . "a6df411fbfb21ca3"), Math::BigInt->new ("0x" . "dc0731d78f8795da"),
  Math::BigInt->new ("0x" . "536fa08fdfd90e51"), Math::BigInt->new ("0x" . "29b7d047efec8728"),
);

sub crc64
{
  my $h = shift;

  my $data = shift;

  my @datas = split "", $data;

  for (my $i = 0; $i < scalar @datas; $i++)
  {
    $h = $tbl[(($h >> 0) & 0xff) ^ ord ($datas[$i])] ^ ($h >> 8);
  }

  return $h;
}

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;

  my $iv = Math::BigInt->new ("0x" . $salt);

  my $checksum = crc64 ($iv, $word);

  my $hash = sprintf ("%016x:%016x", $checksum, $iv);

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

  return ($new_hash, $word);
}

1;
