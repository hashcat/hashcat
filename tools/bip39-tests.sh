# Runs tests of the BIP39 directly against hashcat

set -e

TEST1="XPUB:m/:coral dice harvest:xpub661MyMwAqRbcFaizXLqdLrqBkUJo4JyyXYNucU2hWQBDfhmCd3TL7USdpjhUddedvEiSo31BRg9QB4a5PNKcuQRWT6DA2YveGA2tzsqZQwg"
PASS1="hashca?4"

TEST2="P2PKH:m/44h/0h/0h/0/0:balcony catalog winner letter alley this:1B2hrNm7JGW6Wenf8oMvjWB3DPT9H9vAJ9"
PASS2="hashca?4"

TEST3="P2PKH-P2WPKH:m/49h/0h/0h/0/1:cage keep stone swarm open race toward state subway dutch extra short purpose interest enough idle found guilt will salt mixed boil heavy thing:361yU4TkuRSLTdTkfEUbWGfTJgJjFDZUvG"
PASS3="hashca?4"

TEST4="P2PWPKH:m/84h/0h/0h/0/2:donate dolphin bachelor excess stuff flower spread crazy scorpion zoo skull lottery:bc1q490ra0dcf4l58jzt2445akrxpj6aftkfdvs8n7"
PASS4="hashca?4"

# security sugar abandon diamond abandon orient zoo example crane fruit senior decade
TEST5="P2PWPKH:m/84h/0h/0h/0/0:security sugar ? diamond ? orient ? example crane fruit senior ?:bc1q6dlx8mxcxm3qterx35cul7z76v975tf2vq06yr"
PASS5="5656?1?2?3hashcat"

if [ -z $1 ] || [ -z $2 ]; then
  echo "Usage ./tools/bip39-tests.sh <test|run|bench> <#|all>"
  exit -1
fi

rm -f hashcat.potfile

for i in $(seq 1 5);
do
  if [[ "$2" = "$i" ]] || [[ "$2" = "all" ]]; then
    echo "Running $1 #$i"
    TEST="TEST$i"
    PASS="PASS$i"
    if [ $1 = "test" ]; then
      ./hashcat -m 28510 -a 3 --force -n 1 -u 1 -T 1 -1 T -2 u -3 S -4 t "${!TEST}" "${!PASS}"
    elif [ $1 = "run" ]; then
      ./hashcat -m 28510 -a 3 -1 charsets/bin/5bit.hcchr -2 charsets/bin/6bit.hcchr -3 charsets/bin/7bit.hcchr -4 ?l "${!TEST}" "${!PASS}"
    elif [ $1 = "bench" ]; then
      ./hashcat -m 28510 -a 3 -1 charsets/bin/5bit.hcchr -2 charsets/bin/6bit.hcchr -3 charsets/bin/7bit.hcchr -4 ?l --status "${!TEST}" "?1?2?1?2?1?2?3?l"
    fi
  fi
done

echo -e "\nResults (should be 5 if running all tests):"
cat hashcat.potfile