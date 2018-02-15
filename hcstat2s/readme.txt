This is a collection of hcstat2 files for Hashcat. These are used in -a 3 to replace the
built in hashcat hcstat file which is trained on rockyou.txt

These adjust the marvok model and per position generators. Use this if you want to adjust
how a3 does searches.

More of these can be found at https://github.com/evilmog/hashcat-hcstat

To use these run ./hashcat64.bin -a 3 -markov-hcstat all.hcstat2 -m [insert mode] example0.hash [insert mask here]

These can also be used with statsprocessor ./sp64.bin [options] hcstat-file [filtermask]

These files may work out better than the built in or they may not, YMMV

-EvilMog
