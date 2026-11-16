#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib
import hmac
import random

# BIP39 seed recovery. The hash line is the mnemonic with one or two words replaced by a '?'
# placeholder, one of its addresses and the derivation path. The candidate carries only the
# missing words: one word for one placeholder, or two words for two placeholders, either space
# separated or concatenated the way the -a 1 combinator produces them. Two concatenated words can
# split into valid word pairs in more than one way ("canalarm" is "can alarm" and "canal arm"), so
# both the generator and the verifier enumerate every split the kernel would try.

P  = 2**256 - 2**32 - 977
N  = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
GX = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
GY = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8

WORDLIST = (
  "abandon ability able about above absent absorb abstract absurd abuse access accident account accuse achieve acid "
  "acoustic acquire across act action actor actress actual adapt add addict address adjust admit adult advance "
  "advice aerobic affair afford afraid again age agent agree ahead aim air airport aisle alarm album "
  "alcohol alert alien all alley allow almost alone alpha already also alter always amateur amazing among "
  "amount amused analyst anchor ancient anger angle angry animal ankle announce annual another answer antenna antique "
  "anxiety any apart apology appear apple approve april arch arctic area arena argue arm armed armor "
  "army around arrange arrest arrive arrow art artefact artist artwork ask aspect assault asset assist assume "
  "asthma athlete atom attack attend attitude attract auction audit august aunt author auto autumn average avocado "
  "avoid awake aware away awesome awful awkward axis baby bachelor bacon badge bag balance balcony ball "
  "bamboo banana banner bar barely bargain barrel base basic basket battle beach bean beauty because become "
  "beef before begin behave behind believe below belt bench benefit best betray better between beyond bicycle "
  "bid bike bind biology bird birth bitter black blade blame blanket blast bleak bless blind blood "
  "blossom blouse blue blur blush board boat body boil bomb bone bonus book boost border boring "
  "borrow boss bottom bounce box boy bracket brain brand brass brave bread breeze brick bridge brief "
  "bright bring brisk broccoli broken bronze broom brother brown brush bubble buddy budget buffalo build bulb "
  "bulk bullet bundle bunker burden burger burst bus business busy butter buyer buzz cabbage cabin cable "
  "cactus cage cake call calm camera camp can canal cancel candy cannon canoe canvas canyon capable "
  "capital captain car carbon card cargo carpet carry cart case cash casino castle casual cat catalog "
  "catch category cattle caught cause caution cave ceiling celery cement census century cereal certain chair chalk "
  "champion change chaos chapter charge chase chat cheap check cheese chef cherry chest chicken chief child "
  "chimney choice choose chronic chuckle chunk churn cigar cinnamon circle citizen city civil claim clap clarify "
  "claw clay clean clerk clever click client cliff climb clinic clip clock clog close cloth cloud "
  "clown club clump cluster clutch coach coast coconut code coffee coil coin collect color column combine "
  "come comfort comic common company concert conduct confirm congress connect consider control convince cook cool copper "
  "copy coral core corn correct cost cotton couch country couple course cousin cover coyote crack cradle "
  "craft cram crane crash crater crawl crazy cream credit creek crew cricket crime crisp critic crop "
  "cross crouch crowd crucial cruel cruise crumble crunch crush cry crystal cube culture cup cupboard curious "
  "current curtain curve cushion custom cute cycle dad damage damp dance danger daring dash daughter dawn "
  "day deal debate debris decade december decide decline decorate decrease deer defense define defy degree delay "
  "deliver demand demise denial dentist deny depart depend deposit depth deputy derive describe desert design desk "
  "despair destroy detail detect develop device devote diagram dial diamond diary dice diesel diet differ digital "
  "dignity dilemma dinner dinosaur direct dirt disagree discover disease dish dismiss disorder display distance divert divide "
  "divorce dizzy doctor document dog doll dolphin domain donate donkey donor door dose double dove draft "
  "dragon drama drastic draw dream dress drift drill drink drip drive drop drum dry duck dumb "
  "dune during dust dutch duty dwarf dynamic eager eagle early earn earth easily east easy echo "
  "ecology economy edge edit educate effort egg eight either elbow elder electric elegant element elephant elevator "
  "elite else embark embody embrace emerge emotion employ empower empty enable enact end endless endorse enemy "
  "energy enforce engage engine enhance enjoy enlist enough enrich enroll ensure enter entire entry envelope episode "
  "equal equip era erase erode erosion error erupt escape essay essence estate eternal ethics evidence evil "
  "evoke evolve exact example excess exchange excite exclude excuse execute exercise exhaust exhibit exile exist exit "
  "exotic expand expect expire explain expose express extend extra eye eyebrow fabric face faculty fade faint "
  "faith fall false fame family famous fan fancy fantasy farm fashion fat fatal father fatigue fault "
  "favorite feature february federal fee feed feel female fence festival fetch fever few fiber fiction field "
  "figure file film filter final find fine finger finish fire firm first fiscal fish fit fitness "
  "fix flag flame flash flat flavor flee flight flip float flock floor flower fluid flush fly "
  "foam focus fog foil fold follow food foot force forest forget fork fortune forum forward fossil "
  "foster found fox fragile frame frequent fresh friend fringe frog front frost frown frozen fruit fuel "
  "fun funny furnace fury future gadget gain galaxy gallery game gap garage garbage garden garlic garment "
  "gas gasp gate gather gauge gaze general genius genre gentle genuine gesture ghost giant gift giggle "
  "ginger giraffe girl give glad glance glare glass glide glimpse globe gloom glory glove glow glue "
  "goat goddess gold good goose gorilla gospel gossip govern gown grab grace grain grant grape grass "
  "gravity great green grid grief grit grocery group grow grunt guard guess guide guilt guitar gun "
  "gym habit hair half hammer hamster hand happy harbor hard harsh harvest hat have hawk hazard "
  "head health heart heavy hedgehog height hello helmet help hen hero hidden high hill hint hip "
  "hire history hobby hockey hold hole holiday hollow home honey hood hope horn horror horse hospital "
  "host hotel hour hover hub huge human humble humor hundred hungry hunt hurdle hurry hurt husband "
  "hybrid ice icon idea identify idle ignore ill illegal illness image imitate immense immune impact impose "
  "improve impulse inch include income increase index indicate indoor industry infant inflict inform inhale inherit initial "
  "inject injury inmate inner innocent input inquiry insane insect inside inspire install intact interest into invest "
  "invite involve iron island isolate issue item ivory jacket jaguar jar jazz jealous jeans jelly jewel "
  "job join joke journey joy judge juice jump jungle junior junk just kangaroo keen keep ketchup "
  "key kick kid kidney kind kingdom kiss kit kitchen kite kitten kiwi knee knife knock know "
  "lab label labor ladder lady lake lamp language laptop large later latin laugh laundry lava law "
  "lawn lawsuit layer lazy leader leaf learn leave lecture left leg legal legend leisure lemon lend "
  "length lens leopard lesson letter level liar liberty library license life lift light like limb limit "
  "link lion liquid list little live lizard load loan lobster local lock logic lonely long loop "
  "lottery loud lounge love loyal lucky luggage lumber lunar lunch luxury lyrics machine mad magic magnet "
  "maid mail main major make mammal man manage mandate mango mansion manual maple marble march margin "
  "marine market marriage mask mass master match material math matrix matter maximum maze meadow mean measure "
  "meat mechanic medal media melody melt member memory mention menu mercy merge merit merry mesh message "
  "metal method middle midnight milk million mimic mind minimum minor minute miracle mirror misery miss mistake "
  "mix mixed mixture mobile model modify mom moment monitor monkey monster month moon moral more morning "
  "mosquito mother motion motor mountain mouse move movie much muffin mule multiply muscle museum mushroom music "
  "must mutual myself mystery myth naive name napkin narrow nasty nation nature near neck need negative "
  "neglect neither nephew nerve nest net network neutral never news next nice night noble noise nominee "
  "noodle normal north nose notable note nothing notice novel now nuclear number nurse nut oak obey "
  "object oblige obscure observe obtain obvious occur ocean october odor off offer office often oil okay "
  "old olive olympic omit once one onion online only open opera opinion oppose option orange orbit "
  "orchard order ordinary organ orient original orphan ostrich other outdoor outer output outside oval oven over "
  "own owner oxygen oyster ozone pact paddle page pair palace palm panda panel panic panther paper "
  "parade parent park parrot party pass patch path patient patrol pattern pause pave payment peace peanut "
  "pear peasant pelican pen penalty pencil people pepper perfect permit person pet phone photo phrase physical "
  "piano picnic picture piece pig pigeon pill pilot pink pioneer pipe pistol pitch pizza place planet "
  "plastic plate play please pledge pluck plug plunge poem poet point polar pole police pond pony "
  "pool popular portion position possible post potato pottery poverty powder power practice praise predict prefer prepare "
  "present pretty prevent price pride primary print priority prison private prize problem process produce profit program "
  "project promote proof property prosper protect proud provide public pudding pull pulp pulse pumpkin punch pupil "
  "puppy purchase purity purpose purse push put puzzle pyramid quality quantum quarter question quick quit quiz "
  "quote rabbit raccoon race rack radar radio rail rain raise rally ramp ranch random range rapid "
  "rare rate rather raven raw razor ready real reason rebel rebuild recall receive recipe record recycle "
  "reduce reflect reform refuse region regret regular reject relax release relief rely remain remember remind remove "
  "render renew rent reopen repair repeat replace report require rescue resemble resist resource response result retire "
  "retreat return reunion reveal review reward rhythm rib ribbon rice rich ride ridge rifle right rigid "
  "ring riot ripple risk ritual rival river road roast robot robust rocket romance roof rookie room "
  "rose rotate rough round route royal rubber rude rug rule run runway rural sad saddle sadness "
  "safe sail salad salmon salon salt salute same sample sand satisfy satoshi sauce sausage save say "
  "scale scan scare scatter scene scheme school science scissors scorpion scout scrap screen script scrub sea "
  "search season seat second secret section security seed seek segment select sell seminar senior sense sentence "
  "series service session settle setup seven shadow shaft shallow share shed shell sheriff shield shift shine "
  "ship shiver shock shoe shoot shop short shoulder shove shrimp shrug shuffle shy sibling sick side "
  "siege sight sign silent silk silly silver similar simple since sing siren sister situate six size "
  "skate sketch ski skill skin skirt skull slab slam sleep slender slice slide slight slim slogan "
  "slot slow slush small smart smile smoke smooth snack snake snap sniff snow soap soccer social "
  "sock soda soft solar soldier solid solution solve someone song soon sorry sort soul sound soup "
  "source south space spare spatial spawn speak special speed spell spend sphere spice spider spike spin "
  "spirit split spoil sponsor spoon sport spot spray spread spring spy square squeeze squirrel stable stadium "
  "staff stage stairs stamp stand start state stay steak steel stem step stereo stick still sting "
  "stock stomach stone stool story stove strategy street strike strong struggle student stuff stumble style subject "
  "submit subway success such sudden suffer sugar suggest suit summer sun sunny sunset super supply supreme "
  "sure surface surge surprise surround survey suspect sustain swallow swamp swap swarm swear sweet swift swim "
  "swing switch sword symbol symptom syrup system table tackle tag tail talent talk tank tape target "
  "task taste tattoo taxi teach team tell ten tenant tennis tent term test text thank that "
  "theme then theory there they thing this thought three thrive throw thumb thunder ticket tide tiger "
  "tilt timber time tiny tip tired tissue title toast tobacco today toddler toe together toilet token "
  "tomato tomorrow tone tongue tonight tool tooth top topic topple torch tornado tortoise toss total tourist "
  "toward tower town toy track trade traffic tragic train transfer trap trash travel tray treat tree "
  "trend trial tribe trick trigger trim trip trophy trouble truck true truly trumpet trust truth try "
  "tube tuition tumble tuna tunnel turkey turn turtle twelve twenty twice twin twist two type typical "
  "ugly umbrella unable unaware uncle uncover under undo unfair unfold unhappy uniform unique unit universe unknown "
  "unlock until unusual unveil update upgrade uphold upon upper upset urban urge usage use used useful "
  "useless usual utility vacant vacuum vague valid valley valve van vanish vapor various vast vault vehicle "
  "velvet vendor venture venue verb verify version very vessel veteran viable vibrant vicious victory video view "
  "village vintage violin virtual virus visa visit visual vital vivid vocal voice void volcano volume vote "
  "voyage wage wagon wait walk wall walnut want warfare warm warrior wash wasp waste water wave "
  "way wealth weapon wear weasel weather web wedding weekend weird welcome west wet whale what wheat "
  "wheel when where whip whisper wide width wife wild will win window wine wing wink winner "
  "winter wire wisdom wise wish witness wolf woman wonder wood wool word work world worry worth "
  "wrap wreck wrestle wrist write wrong yard year yellow you young youth zebra zero zone zoo "
).split()

WORDS = WORDLIST

WORDSET = set(WORDS)

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def point_add(p1, p2):
  if p1 is None:
    return p2

  if p2 is None:
    return p1

  x1, y1 = p1
  x2, y2 = p2

  if x1 == x2 and (y1 + y2) % P == 0:
    return None

  if x1 == x2 and y1 == y2:
    lam = (3 * x1 * x1) * pow(2 * y1, -1, P) % P
  else:
    lam = (y2 - y1) * pow(x2 - x1, -1, P) % P

  x3 = (lam * lam - x1 - x2) % P
  y3 = (lam * (x1 - x3) - y1) % P

  return (x3, y3)


def scalar_mult(k):
  result = None

  addend = (GX, GY)

  while k:
    if k & 1:
      result = point_add(result, addend)

    addend = point_add(addend, addend)

    k >>= 1

  return result


def serialize_point(point):
  prefix = b"\x03" if (point[1] & 1) else b"\x02"

  return prefix + point[0].to_bytes(32, "big")


def hash160(data):
  sha = hashlib.sha256(data).digest()

  try:
    ripemd = hashlib.new("ripemd160")
    ripemd.update(sha)

    return ripemd.digest()
  except ValueError:
    # OpenSSL 3 moved RIPEMD-160 to the legacy provider, which some builds leave out

    from Crypto.Hash import RIPEMD160

    ripemd = RIPEMD160.new()
    ripemd.update(sha)

    return ripemd.digest()


def base58check(payload):
  raw = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]

  value = int.from_bytes(raw, "big")
  out   = ""

  while value:
    value, rest = divmod(value, 58)
    out = B58[rest] + out

  for byte in raw:
    if byte != 0:
      break

    out = "1" + out

  return out


def bech32_encode(hrp, witver, witprog):
  def polymod(values):
    gen = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
      top = chk >> 25
      chk = ((chk & 0x1ffffff) << 5) ^ v
      for i in range(5):
        if (top >> i) & 1:
          chk ^= gen[i]
    return chk

  def convertbits(data, fromb, tob):
    acc = 0
    bits = 0
    out = []
    maxv = (1 << tob) - 1
    for v in data:
      acc = (acc << fromb) | v
      bits += fromb
      while bits >= tob:
        bits -= tob
        out.append((acc >> bits) & maxv)
    if bits:
      out.append((acc << (tob - bits)) & maxv)
    return out

  data = [witver] + convertbits(witprog, 8, 5)
  values = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp] + data + [0] * 6
  mod = polymod(values) ^ 1
  checksum = [(mod >> 5 * (5 - i)) & 31 for i in range(6)]

  return hrp + "1" + "".join(BECH32_CHARSET[d] for d in data + checksum)


def child_key(key, chain, index):
  if index >= 0x80000000:
    data = b"\x00" + key.to_bytes(32, "big")
  else:
    data = serialize_point(scalar_mult(key))

  digest = hmac.new(chain, data + index.to_bytes(4, "big"), hashlib.sha512).digest()

  il = int.from_bytes(digest[:32], "big")

  if il >= N:
    return None

  child = (il + key) % N

  if child == 0:
    return None

  return (child, digest[32:])


def expand_path(path):
  # turns "m/44'/0'/0'/0/{0-7}" into a list of fully fixed index lists

  parts = path.split("/")[1:]

  paths = [[]]

  for part in parts:
    hardened = 0

    if part.endswith("'"):
      hardened = 0x80000000
      part = part[:-1]

    if part.startswith("{"):
      body = part[1:-1]

      if "-" in body:
        lo, hi = body.split("-")
        values = range(int(lo), int(hi) + 1)
      else:
        values = [int(v) for v in body.split(",")]
    else:
      values = [int(part)]

    new_paths = []

    for base in paths:
      for value in values:
        new_paths.append(base + [value + hardened])

    paths = new_paths

  return paths


def derive_addresses(mnemonic, path):
  seed = hashlib.pbkdf2_hmac("sha512", mnemonic.encode(), b"mnemonic", 2048, 64)

  master = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()

  out = []

  for indices in expand_path(path):
    key   = int.from_bytes(master[:32], "big")
    chain = master[32:]

    ok = True

    for index in indices:
      node = child_key(key, chain, index)

      if node is None:
        ok = False
        break

      key, chain = node

    if not ok:
      continue

    h160 = hash160(serialize_point(scalar_mult(key)))

    out.append((
      base58check(b"\x00" + h160),
      base58check(b"\x05" + hash160(b"\x00\x14" + h160)),
      bech32_encode("bc", 0, h160),
    ))

  return out


def checksum_ok(word_list):
  bits = "".join(bin(WORDS.index(w))[2:].zfill(11) for w in word_list)

  ent_len = len(word_list) * 32 // 3 // 8

  ent = int(bits[:ent_len * 8], 2).to_bytes(ent_len, "big")
  cs  = int(bits[ent_len * 8:], 2)

  digest = hashlib.sha256(ent).digest()

  cs_want = int.from_bytes(digest, "big") >> (256 - len(word_list) // 3)

  return cs == cs_want


def candidate_splits(word):
  # every way the candidate reads as one word, or as two listed words, in the order the kernel
  # tries them: a space separated pair first, then concatenation splits from the left

  if isinstance(word, bytes):
    word = word.decode()

  out = []

  if " " in word:
    left, right = word.split(" ", 1)

    if left in WORDSET and right in WORDSET:
      out.append((left, right))

    return out

  if word in WORDSET:
    out.append((word,))

  for i in range(3, len(word) - 2):
    if word[:i] in WORDSET and word[i:] in WORDSET:
      out.append((word[:i], word[i:]))

  return out


def module_get_random_password(word):
  digest = hashlib.sha256(word).digest()

  idx1 = int.from_bytes(digest[0:2], "big") % 2048

  if digest[2] & 1:
    idx2 = int.from_bytes(digest[3:5], "big") % 2048

    return (WORDS[idx1] + WORDS[idx2]).encode()

  return WORDS[idx1].encode()


def module_test_properties():
  return {
    'constraints': {
      'pure': {
        'password_length': [1, 32],
        'salt_length': None,
      },
      'optimized': None,
      'combined_length': None,
    },
  }


def module_generate_hash(word, salt=None, iterations=None):
  if isinstance(word, bytes):
    word = word.decode()

  splits = candidate_splits(word)

  if not splits:
    return None

  candidate_words = splits[0]

  ph_cnt = len(candidate_words)

  word_cnt = random.choice((12, 15, 18, 21, 24))

  positions = random.sample(range(word_cnt), ph_cnt)
  positions.sort()

  while True:
    mnemonic = [random.choice(WORDS) for _ in range(word_cnt)]

    for pos, candidate_word in zip(positions, candidate_words):
      mnemonic[pos] = candidate_word

    if checksum_ok(mnemonic):
      break

  path_kind = random.randrange(4)

  if path_kind == 0:
    path = "m/44'/0'/0'/0/{0-7}"
  elif path_kind == 1:
    path = "m/44'/0'/0'/0/0"
  elif path_kind == 2:
    path = "m/49'/0'/0'/0/0"
  else:
    path = "m/84'/0'/0'/0/0"

  addresses = derive_addresses(" ".join(mnemonic), path)

  p2pkh, p2sh, p2wpkh = addresses[random.randrange(len(addresses))]

  if path_kind == 2:
    address = p2sh
  elif path_kind == 3:
    address = p2wpkh
  else:
    address = p2pkh

  skeleton = ["?" if i in positions else w for i, w in enumerate(mnemonic)]

  return "%s:%s:%s" % (" ".join(skeleton), address, path)


def module_verify_hash(line):
  idx = line.rfind(b":")

  if idx < 1:
    return None

  hash_in = line[:idx].decode(errors="replace")
  word    = line[idx + 1:]

  parts = hash_in.split(":")

  if len(parts) != 3:
    return None

  skeleton, address, path = parts

  tokens = skeleton.split(" ")

  if len(tokens) not in (12, 15, 18, 21, 24):
    return None

  ph_cnt = sum(1 for t in tokens if t in ("?", "*"))

  if ph_cnt < 1 or ph_cnt > 2:
    return None

  for split in candidate_splits(word):
    if len(split) != ph_cnt:
      continue

    mnemonic = []

    ph = 0

    for token in tokens:
      if token in ("?", "*"):
        mnemonic.append(split[ph])
        ph += 1
      else:
        mnemonic.append(token)

    for addresses in derive_addresses(" ".join(mnemonic), path):
      if address in addresses:
        return (hash_in, word)

  return None
