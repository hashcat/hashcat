/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "modules.h"
#include "bitops.h"
#include "convert.h"
#include "shared.h"
#include "parser.h"
#include "memory.h"
#include "emu_inc_hash_base58.h"
#include "emu_inc_hash_md5.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>

static const u32   ATTACK_EXEC    = ATTACK_EXEC_OUTSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_5;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_CRYPTOCURRENCY_WALLET;
static const char *HASH_NAME      = "BIP39 Seed Recovery (ASCII, P2SH/P2PKH/P2WPKH)";
static const u64   KERN_TYPE      = 36001;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_MULTIHASH_DESPITE_ESALT;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "season";
static const char *ST_HASH        = "abstract lunar skin valve feed ? argue nut dinner hood carbon excuse:1PqtiyoSVEqUmSPMHVTLDmGxoCxW6pqmy7:m/44'/0'/0'/0/0";

#define BIP39S_MAX_WORDS                 24u
#define BIP39S_PLACEHOLDER        0xffffffffu
#define BIP39S_MAX_CANDIDATE_LEN         17u

#include "hooks_common.c"

// The derivation path parser, the address decoders and the tuning bounds are shared with mode
// 36000 through bip39_common.c, the way the scrypt modules share scrypt_common.c.

#include "bip39_common.c"

typedef struct bip39s_skeleton
{
  u32 skeleton_len;
  u32 address_len;
  u32 path_len;
  u32 path_depth;
  u32 target_type;
  u32 word_cnt;
  u32 ph_cnt;
  u32 variant_slots;

  u32 path_indices[BIP39_MAX_PATH_DEPTH];
  u32 path_kind[BIP39_MAX_PATH_DEPTH];
  u32 path_dynamic_count;
  u32 dynamic_value_total;
  u64 path_combo_total;
  bip39_dynamic_segment_t dynamic_segments[BIP39_MAX_DYNAMIC_SEGMENTS];
  u32 dynamic_values[BIP39_MAX_DYNAMIC_VALUES];
  u32 target_hash[5];
  u32 word_idx[BIP39S_MAX_WORDS];

  u8 skeleton[512];
  u8 address[64];
  u8 path[64];

} bip39s_skeleton_t;

static u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return (u64) sizeof (bip39s_skeleton_t);
}

typedef struct bip39s_tmp
{
  u64 master[2][8];

  u32 prefix_key[2][8];
  u32 prefix_chain[2][8];

  u32 prefix_pub_x[2][8];
  u32 prefix_pub_tag[2];

  u32 variant_ok[2];

  u32 hit[BIP39_MAX_HITS];
  u32 hit_cnt;

  u32 valid;

} bip39s_tmp_t;

static u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return (u64) sizeof (bip39s_tmp_t);
}

// BIP39 English wordlist, 2048 words, https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt

static const char *const bip39_english_words[2048] =
{
  "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract",
  "absurd", "abuse", "access", "accident", "account", "accuse", "achieve", "acid",
  "acoustic", "acquire", "across", "act", "action", "actor", "actress", "actual",
  "adapt", "add", "addict", "address", "adjust", "admit", "adult", "advance",
  "advice", "aerobic", "affair", "afford", "afraid", "again", "age", "agent",
  "agree", "ahead", "aim", "air", "airport", "aisle", "alarm", "album",
  "alcohol", "alert", "alien", "all", "alley", "allow", "almost", "alone",
  "alpha", "already", "also", "alter", "always", "amateur", "amazing", "among",
  "amount", "amused", "analyst", "anchor", "ancient", "anger", "angle", "angry",
  "animal", "ankle", "announce", "annual", "another", "answer", "antenna", "antique",
  "anxiety", "any", "apart", "apology", "appear", "apple", "approve", "april",
  "arch", "arctic", "area", "arena", "argue", "arm", "armed", "armor",
  "army", "around", "arrange", "arrest", "arrive", "arrow", "art", "artefact",
  "artist", "artwork", "ask", "aspect", "assault", "asset", "assist", "assume",
  "asthma", "athlete", "atom", "attack", "attend", "attitude", "attract", "auction",
  "audit", "august", "aunt", "author", "auto", "autumn", "average", "avocado",
  "avoid", "awake", "aware", "away", "awesome", "awful", "awkward", "axis",
  "baby", "bachelor", "bacon", "badge", "bag", "balance", "balcony", "ball",
  "bamboo", "banana", "banner", "bar", "barely", "bargain", "barrel", "base",
  "basic", "basket", "battle", "beach", "bean", "beauty", "because", "become",
  "beef", "before", "begin", "behave", "behind", "believe", "below", "belt",
  "bench", "benefit", "best", "betray", "better", "between", "beyond", "bicycle",
  "bid", "bike", "bind", "biology", "bird", "birth", "bitter", "black",
  "blade", "blame", "blanket", "blast", "bleak", "bless", "blind", "blood",
  "blossom", "blouse", "blue", "blur", "blush", "board", "boat", "body",
  "boil", "bomb", "bone", "bonus", "book", "boost", "border", "boring",
  "borrow", "boss", "bottom", "bounce", "box", "boy", "bracket", "brain",
  "brand", "brass", "brave", "bread", "breeze", "brick", "bridge", "brief",
  "bright", "bring", "brisk", "broccoli", "broken", "bronze", "broom", "brother",
  "brown", "brush", "bubble", "buddy", "budget", "buffalo", "build", "bulb",
  "bulk", "bullet", "bundle", "bunker", "burden", "burger", "burst", "bus",
  "business", "busy", "butter", "buyer", "buzz", "cabbage", "cabin", "cable",
  "cactus", "cage", "cake", "call", "calm", "camera", "camp", "can",
  "canal", "cancel", "candy", "cannon", "canoe", "canvas", "canyon", "capable",
  "capital", "captain", "car", "carbon", "card", "cargo", "carpet", "carry",
  "cart", "case", "cash", "casino", "castle", "casual", "cat", "catalog",
  "catch", "category", "cattle", "caught", "cause", "caution", "cave", "ceiling",
  "celery", "cement", "census", "century", "cereal", "certain", "chair", "chalk",
  "champion", "change", "chaos", "chapter", "charge", "chase", "chat", "cheap",
  "check", "cheese", "chef", "cherry", "chest", "chicken", "chief", "child",
  "chimney", "choice", "choose", "chronic", "chuckle", "chunk", "churn", "cigar",
  "cinnamon", "circle", "citizen", "city", "civil", "claim", "clap", "clarify",
  "claw", "clay", "clean", "clerk", "clever", "click", "client", "cliff",
  "climb", "clinic", "clip", "clock", "clog", "close", "cloth", "cloud",
  "clown", "club", "clump", "cluster", "clutch", "coach", "coast", "coconut",
  "code", "coffee", "coil", "coin", "collect", "color", "column", "combine",
  "come", "comfort", "comic", "common", "company", "concert", "conduct", "confirm",
  "congress", "connect", "consider", "control", "convince", "cook", "cool", "copper",
  "copy", "coral", "core", "corn", "correct", "cost", "cotton", "couch",
  "country", "couple", "course", "cousin", "cover", "coyote", "crack", "cradle",
  "craft", "cram", "crane", "crash", "crater", "crawl", "crazy", "cream",
  "credit", "creek", "crew", "cricket", "crime", "crisp", "critic", "crop",
  "cross", "crouch", "crowd", "crucial", "cruel", "cruise", "crumble", "crunch",
  "crush", "cry", "crystal", "cube", "culture", "cup", "cupboard", "curious",
  "current", "curtain", "curve", "cushion", "custom", "cute", "cycle", "dad",
  "damage", "damp", "dance", "danger", "daring", "dash", "daughter", "dawn",
  "day", "deal", "debate", "debris", "decade", "december", "decide", "decline",
  "decorate", "decrease", "deer", "defense", "define", "defy", "degree", "delay",
  "deliver", "demand", "demise", "denial", "dentist", "deny", "depart", "depend",
  "deposit", "depth", "deputy", "derive", "describe", "desert", "design", "desk",
  "despair", "destroy", "detail", "detect", "develop", "device", "devote", "diagram",
  "dial", "diamond", "diary", "dice", "diesel", "diet", "differ", "digital",
  "dignity", "dilemma", "dinner", "dinosaur", "direct", "dirt", "disagree", "discover",
  "disease", "dish", "dismiss", "disorder", "display", "distance", "divert", "divide",
  "divorce", "dizzy", "doctor", "document", "dog", "doll", "dolphin", "domain",
  "donate", "donkey", "donor", "door", "dose", "double", "dove", "draft",
  "dragon", "drama", "drastic", "draw", "dream", "dress", "drift", "drill",
  "drink", "drip", "drive", "drop", "drum", "dry", "duck", "dumb",
  "dune", "during", "dust", "dutch", "duty", "dwarf", "dynamic", "eager",
  "eagle", "early", "earn", "earth", "easily", "east", "easy", "echo",
  "ecology", "economy", "edge", "edit", "educate", "effort", "egg", "eight",
  "either", "elbow", "elder", "electric", "elegant", "element", "elephant", "elevator",
  "elite", "else", "embark", "embody", "embrace", "emerge", "emotion", "employ",
  "empower", "empty", "enable", "enact", "end", "endless", "endorse", "enemy",
  "energy", "enforce", "engage", "engine", "enhance", "enjoy", "enlist", "enough",
  "enrich", "enroll", "ensure", "enter", "entire", "entry", "envelope", "episode",
  "equal", "equip", "era", "erase", "erode", "erosion", "error", "erupt",
  "escape", "essay", "essence", "estate", "eternal", "ethics", "evidence", "evil",
  "evoke", "evolve", "exact", "example", "excess", "exchange", "excite", "exclude",
  "excuse", "execute", "exercise", "exhaust", "exhibit", "exile", "exist", "exit",
  "exotic", "expand", "expect", "expire", "explain", "expose", "express", "extend",
  "extra", "eye", "eyebrow", "fabric", "face", "faculty", "fade", "faint",
  "faith", "fall", "false", "fame", "family", "famous", "fan", "fancy",
  "fantasy", "farm", "fashion", "fat", "fatal", "father", "fatigue", "fault",
  "favorite", "feature", "february", "federal", "fee", "feed", "feel", "female",
  "fence", "festival", "fetch", "fever", "few", "fiber", "fiction", "field",
  "figure", "file", "film", "filter", "final", "find", "fine", "finger",
  "finish", "fire", "firm", "first", "fiscal", "fish", "fit", "fitness",
  "fix", "flag", "flame", "flash", "flat", "flavor", "flee", "flight",
  "flip", "float", "flock", "floor", "flower", "fluid", "flush", "fly",
  "foam", "focus", "fog", "foil", "fold", "follow", "food", "foot",
  "force", "forest", "forget", "fork", "fortune", "forum", "forward", "fossil",
  "foster", "found", "fox", "fragile", "frame", "frequent", "fresh", "friend",
  "fringe", "frog", "front", "frost", "frown", "frozen", "fruit", "fuel",
  "fun", "funny", "furnace", "fury", "future", "gadget", "gain", "galaxy",
  "gallery", "game", "gap", "garage", "garbage", "garden", "garlic", "garment",
  "gas", "gasp", "gate", "gather", "gauge", "gaze", "general", "genius",
  "genre", "gentle", "genuine", "gesture", "ghost", "giant", "gift", "giggle",
  "ginger", "giraffe", "girl", "give", "glad", "glance", "glare", "glass",
  "glide", "glimpse", "globe", "gloom", "glory", "glove", "glow", "glue",
  "goat", "goddess", "gold", "good", "goose", "gorilla", "gospel", "gossip",
  "govern", "gown", "grab", "grace", "grain", "grant", "grape", "grass",
  "gravity", "great", "green", "grid", "grief", "grit", "grocery", "group",
  "grow", "grunt", "guard", "guess", "guide", "guilt", "guitar", "gun",
  "gym", "habit", "hair", "half", "hammer", "hamster", "hand", "happy",
  "harbor", "hard", "harsh", "harvest", "hat", "have", "hawk", "hazard",
  "head", "health", "heart", "heavy", "hedgehog", "height", "hello", "helmet",
  "help", "hen", "hero", "hidden", "high", "hill", "hint", "hip",
  "hire", "history", "hobby", "hockey", "hold", "hole", "holiday", "hollow",
  "home", "honey", "hood", "hope", "horn", "horror", "horse", "hospital",
  "host", "hotel", "hour", "hover", "hub", "huge", "human", "humble",
  "humor", "hundred", "hungry", "hunt", "hurdle", "hurry", "hurt", "husband",
  "hybrid", "ice", "icon", "idea", "identify", "idle", "ignore", "ill",
  "illegal", "illness", "image", "imitate", "immense", "immune", "impact", "impose",
  "improve", "impulse", "inch", "include", "income", "increase", "index", "indicate",
  "indoor", "industry", "infant", "inflict", "inform", "inhale", "inherit", "initial",
  "inject", "injury", "inmate", "inner", "innocent", "input", "inquiry", "insane",
  "insect", "inside", "inspire", "install", "intact", "interest", "into", "invest",
  "invite", "involve", "iron", "island", "isolate", "issue", "item", "ivory",
  "jacket", "jaguar", "jar", "jazz", "jealous", "jeans", "jelly", "jewel",
  "job", "join", "joke", "journey", "joy", "judge", "juice", "jump",
  "jungle", "junior", "junk", "just", "kangaroo", "keen", "keep", "ketchup",
  "key", "kick", "kid", "kidney", "kind", "kingdom", "kiss", "kit",
  "kitchen", "kite", "kitten", "kiwi", "knee", "knife", "knock", "know",
  "lab", "label", "labor", "ladder", "lady", "lake", "lamp", "language",
  "laptop", "large", "later", "latin", "laugh", "laundry", "lava", "law",
  "lawn", "lawsuit", "layer", "lazy", "leader", "leaf", "learn", "leave",
  "lecture", "left", "leg", "legal", "legend", "leisure", "lemon", "lend",
  "length", "lens", "leopard", "lesson", "letter", "level", "liar", "liberty",
  "library", "license", "life", "lift", "light", "like", "limb", "limit",
  "link", "lion", "liquid", "list", "little", "live", "lizard", "load",
  "loan", "lobster", "local", "lock", "logic", "lonely", "long", "loop",
  "lottery", "loud", "lounge", "love", "loyal", "lucky", "luggage", "lumber",
  "lunar", "lunch", "luxury", "lyrics", "machine", "mad", "magic", "magnet",
  "maid", "mail", "main", "major", "make", "mammal", "man", "manage",
  "mandate", "mango", "mansion", "manual", "maple", "marble", "march", "margin",
  "marine", "market", "marriage", "mask", "mass", "master", "match", "material",
  "math", "matrix", "matter", "maximum", "maze", "meadow", "mean", "measure",
  "meat", "mechanic", "medal", "media", "melody", "melt", "member", "memory",
  "mention", "menu", "mercy", "merge", "merit", "merry", "mesh", "message",
  "metal", "method", "middle", "midnight", "milk", "million", "mimic", "mind",
  "minimum", "minor", "minute", "miracle", "mirror", "misery", "miss", "mistake",
  "mix", "mixed", "mixture", "mobile", "model", "modify", "mom", "moment",
  "monitor", "monkey", "monster", "month", "moon", "moral", "more", "morning",
  "mosquito", "mother", "motion", "motor", "mountain", "mouse", "move", "movie",
  "much", "muffin", "mule", "multiply", "muscle", "museum", "mushroom", "music",
  "must", "mutual", "myself", "mystery", "myth", "naive", "name", "napkin",
  "narrow", "nasty", "nation", "nature", "near", "neck", "need", "negative",
  "neglect", "neither", "nephew", "nerve", "nest", "net", "network", "neutral",
  "never", "news", "next", "nice", "night", "noble", "noise", "nominee",
  "noodle", "normal", "north", "nose", "notable", "note", "nothing", "notice",
  "novel", "now", "nuclear", "number", "nurse", "nut", "oak", "obey",
  "object", "oblige", "obscure", "observe", "obtain", "obvious", "occur", "ocean",
  "october", "odor", "off", "offer", "office", "often", "oil", "okay",
  "old", "olive", "olympic", "omit", "once", "one", "onion", "online",
  "only", "open", "opera", "opinion", "oppose", "option", "orange", "orbit",
  "orchard", "order", "ordinary", "organ", "orient", "original", "orphan", "ostrich",
  "other", "outdoor", "outer", "output", "outside", "oval", "oven", "over",
  "own", "owner", "oxygen", "oyster", "ozone", "pact", "paddle", "page",
  "pair", "palace", "palm", "panda", "panel", "panic", "panther", "paper",
  "parade", "parent", "park", "parrot", "party", "pass", "patch", "path",
  "patient", "patrol", "pattern", "pause", "pave", "payment", "peace", "peanut",
  "pear", "peasant", "pelican", "pen", "penalty", "pencil", "people", "pepper",
  "perfect", "permit", "person", "pet", "phone", "photo", "phrase", "physical",
  "piano", "picnic", "picture", "piece", "pig", "pigeon", "pill", "pilot",
  "pink", "pioneer", "pipe", "pistol", "pitch", "pizza", "place", "planet",
  "plastic", "plate", "play", "please", "pledge", "pluck", "plug", "plunge",
  "poem", "poet", "point", "polar", "pole", "police", "pond", "pony",
  "pool", "popular", "portion", "position", "possible", "post", "potato", "pottery",
  "poverty", "powder", "power", "practice", "praise", "predict", "prefer", "prepare",
  "present", "pretty", "prevent", "price", "pride", "primary", "print", "priority",
  "prison", "private", "prize", "problem", "process", "produce", "profit", "program",
  "project", "promote", "proof", "property", "prosper", "protect", "proud", "provide",
  "public", "pudding", "pull", "pulp", "pulse", "pumpkin", "punch", "pupil",
  "puppy", "purchase", "purity", "purpose", "purse", "push", "put", "puzzle",
  "pyramid", "quality", "quantum", "quarter", "question", "quick", "quit", "quiz",
  "quote", "rabbit", "raccoon", "race", "rack", "radar", "radio", "rail",
  "rain", "raise", "rally", "ramp", "ranch", "random", "range", "rapid",
  "rare", "rate", "rather", "raven", "raw", "razor", "ready", "real",
  "reason", "rebel", "rebuild", "recall", "receive", "recipe", "record", "recycle",
  "reduce", "reflect", "reform", "refuse", "region", "regret", "regular", "reject",
  "relax", "release", "relief", "rely", "remain", "remember", "remind", "remove",
  "render", "renew", "rent", "reopen", "repair", "repeat", "replace", "report",
  "require", "rescue", "resemble", "resist", "resource", "response", "result", "retire",
  "retreat", "return", "reunion", "reveal", "review", "reward", "rhythm", "rib",
  "ribbon", "rice", "rich", "ride", "ridge", "rifle", "right", "rigid",
  "ring", "riot", "ripple", "risk", "ritual", "rival", "river", "road",
  "roast", "robot", "robust", "rocket", "romance", "roof", "rookie", "room",
  "rose", "rotate", "rough", "round", "route", "royal", "rubber", "rude",
  "rug", "rule", "run", "runway", "rural", "sad", "saddle", "sadness",
  "safe", "sail", "salad", "salmon", "salon", "salt", "salute", "same",
  "sample", "sand", "satisfy", "satoshi", "sauce", "sausage", "save", "say",
  "scale", "scan", "scare", "scatter", "scene", "scheme", "school", "science",
  "scissors", "scorpion", "scout", "scrap", "screen", "script", "scrub", "sea",
  "search", "season", "seat", "second", "secret", "section", "security", "seed",
  "seek", "segment", "select", "sell", "seminar", "senior", "sense", "sentence",
  "series", "service", "session", "settle", "setup", "seven", "shadow", "shaft",
  "shallow", "share", "shed", "shell", "sheriff", "shield", "shift", "shine",
  "ship", "shiver", "shock", "shoe", "shoot", "shop", "short", "shoulder",
  "shove", "shrimp", "shrug", "shuffle", "shy", "sibling", "sick", "side",
  "siege", "sight", "sign", "silent", "silk", "silly", "silver", "similar",
  "simple", "since", "sing", "siren", "sister", "situate", "six", "size",
  "skate", "sketch", "ski", "skill", "skin", "skirt", "skull", "slab",
  "slam", "sleep", "slender", "slice", "slide", "slight", "slim", "slogan",
  "slot", "slow", "slush", "small", "smart", "smile", "smoke", "smooth",
  "snack", "snake", "snap", "sniff", "snow", "soap", "soccer", "social",
  "sock", "soda", "soft", "solar", "soldier", "solid", "solution", "solve",
  "someone", "song", "soon", "sorry", "sort", "soul", "sound", "soup",
  "source", "south", "space", "spare", "spatial", "spawn", "speak", "special",
  "speed", "spell", "spend", "sphere", "spice", "spider", "spike", "spin",
  "spirit", "split", "spoil", "sponsor", "spoon", "sport", "spot", "spray",
  "spread", "spring", "spy", "square", "squeeze", "squirrel", "stable", "stadium",
  "staff", "stage", "stairs", "stamp", "stand", "start", "state", "stay",
  "steak", "steel", "stem", "step", "stereo", "stick", "still", "sting",
  "stock", "stomach", "stone", "stool", "story", "stove", "strategy", "street",
  "strike", "strong", "struggle", "student", "stuff", "stumble", "style", "subject",
  "submit", "subway", "success", "such", "sudden", "suffer", "sugar", "suggest",
  "suit", "summer", "sun", "sunny", "sunset", "super", "supply", "supreme",
  "sure", "surface", "surge", "surprise", "surround", "survey", "suspect", "sustain",
  "swallow", "swamp", "swap", "swarm", "swear", "sweet", "swift", "swim",
  "swing", "switch", "sword", "symbol", "symptom", "syrup", "system", "table",
  "tackle", "tag", "tail", "talent", "talk", "tank", "tape", "target",
  "task", "taste", "tattoo", "taxi", "teach", "team", "tell", "ten",
  "tenant", "tennis", "tent", "term", "test", "text", "thank", "that",
  "theme", "then", "theory", "there", "they", "thing", "this", "thought",
  "three", "thrive", "throw", "thumb", "thunder", "ticket", "tide", "tiger",
  "tilt", "timber", "time", "tiny", "tip", "tired", "tissue", "title",
  "toast", "tobacco", "today", "toddler", "toe", "together", "toilet", "token",
  "tomato", "tomorrow", "tone", "tongue", "tonight", "tool", "tooth", "top",
  "topic", "topple", "torch", "tornado", "tortoise", "toss", "total", "tourist",
  "toward", "tower", "town", "toy", "track", "trade", "traffic", "tragic",
  "train", "transfer", "trap", "trash", "travel", "tray", "treat", "tree",
  "trend", "trial", "tribe", "trick", "trigger", "trim", "trip", "trophy",
  "trouble", "truck", "true", "truly", "trumpet", "trust", "truth", "try",
  "tube", "tuition", "tumble", "tuna", "tunnel", "turkey", "turn", "turtle",
  "twelve", "twenty", "twice", "twin", "twist", "two", "type", "typical",
  "ugly", "umbrella", "unable", "unaware", "uncle", "uncover", "under", "undo",
  "unfair", "unfold", "unhappy", "uniform", "unique", "unit", "universe", "unknown",
  "unlock", "until", "unusual", "unveil", "update", "upgrade", "uphold", "upon",
  "upper", "upset", "urban", "urge", "usage", "use", "used", "useful",
  "useless", "usual", "utility", "vacant", "vacuum", "vague", "valid", "valley",
  "valve", "van", "vanish", "vapor", "various", "vast", "vault", "vehicle",
  "velvet", "vendor", "venture", "venue", "verb", "verify", "version", "very",
  "vessel", "veteran", "viable", "vibrant", "vicious", "victory", "video", "view",
  "village", "vintage", "violin", "virtual", "virus", "visa", "visit", "visual",
  "vital", "vivid", "vocal", "voice", "void", "volcano", "volume", "vote",
  "voyage", "wage", "wagon", "wait", "walk", "wall", "walnut", "want",
  "warfare", "warm", "warrior", "wash", "wasp", "waste", "water", "wave",
  "way", "wealth", "weapon", "wear", "weasel", "weather", "web", "wedding",
  "weekend", "weird", "welcome", "west", "wet", "whale", "what", "wheat",
  "wheel", "when", "where", "whip", "whisper", "wide", "width", "wife",
  "wild", "will", "win", "window", "wine", "wing", "wink", "winner",
  "winter", "wire", "wisdom", "wise", "wish", "witness", "wolf", "woman",
  "wonder", "wood", "wool", "word", "work", "world", "worry", "worth",
  "wrap", "wreck", "wrestle", "wrist", "write", "wrong", "yard", "year",
  "yellow", "you", "young", "youth", "zebra", "zero", "zone", "zoo"
};

// Hashes that share a skeleton, a target type and a derivation path share a salt, and the address
// is deliberately left out so one run covers several addresses of the same wallet. Those three are
// also the only esalt fields the kernels read, which is what makes OPTS_TYPE_MULTIHASH_DESPITE_ESALT
// safe here. The per-address target lives in the digest, not the esalt.

static void bip39s_set_salt_key (const bip39s_skeleton_t *bip39s, salt_t *salt)
{
  md5_ctx_t md5_ctx;

  md5_init (&md5_ctx);
  md5_update (&md5_ctx, &bip39s->target_type, sizeof (bip39s->target_type));
  md5_update (&md5_ctx, &bip39s->skeleton_len, sizeof (bip39s->skeleton_len));
  md5_update (&md5_ctx, (const u32 *) bip39s->skeleton, bip39s->skeleton_len);
  md5_update (&md5_ctx, &bip39s->path_len, sizeof (bip39s->path_len));
  md5_update (&md5_ctx, (const u32 *) bip39s->path, bip39s->path_len);
  md5_final (&md5_ctx);

  salt->salt_buf[0] = md5_ctx.h[0];
  salt->salt_buf[1] = md5_ctx.h[1];
  salt->salt_buf[2] = md5_ctx.h[2];
  salt->salt_buf[3] = md5_ctx.h[3];
  salt->salt_len = 16;
}

static int bip39s_word_index (const u8 *word, const u32 word_len)
{
  if ((word_len < 3) || (word_len > 8)) return -1;

  char needle[9];

  for (u32 i = 0; i < word_len; i++)
  {
    const u8 c = word[i];

    if ((c < 'a') || (c > 'z')) return -1;

    needle[i] = (char) c;
  }

  needle[word_len] = 0;

  u32 lo = 0;
  u32 hi = 2048;

  while (lo < hi)
  {
    const u32 mid = (lo + hi) / 2;

    const int cmp = strcmp (needle, bip39_english_words[mid]);

    if (cmp == 0) return (int) mid;

    if (cmp > 0)
    {
      lo = mid + 1;
    }
    else
    {
      hi = mid;
    }
  }

  return -1;
}

// The skeleton is the mnemonic with one or two words replaced by a '?' or '*' placeholder. Words
// are separated by single spaces, the word count must be a BIP39 sentence length and every known
// word must be on the list.

static int bip39s_parse_skeleton (const u8 *skeleton_pos, const u32 skeleton_len, bip39s_skeleton_t *bip39s)
{
  u32 word_cnt = 0;
  u32 ph_cnt = 0;

  const u8 *p = skeleton_pos;
  const u8 *end = skeleton_pos + skeleton_len;

  while (p < end)
  {
    const u8 *word_start = p;

    while ((p < end) && (*p != ' ')) p++;

    const u32 word_len = (u32) (p - word_start);

    if (word_len == 0) return PARSER_HASH_VALUE;

    if (word_cnt >= BIP39S_MAX_WORDS) return PARSER_HASH_VALUE;

    if ((word_len == 1) && ((word_start[0] == '?') || (word_start[0] == '*')))
    {
      bip39s->word_idx[word_cnt] = BIP39S_PLACEHOLDER;

      ph_cnt++;
    }
    else
    {
      const int idx = bip39s_word_index (word_start, word_len);

      if (idx < 0) return PARSER_HASH_VALUE;

      bip39s->word_idx[word_cnt] = (u32) idx;
    }

    word_cnt++;

    if (p < end)
    {
      p++;

      if (p == end) return PARSER_HASH_VALUE;
    }
  }

  if ((word_cnt < 12) || (word_cnt > BIP39S_MAX_WORDS)) return PARSER_HASH_VALUE;

  if ((word_cnt % 3) != 0) return PARSER_HASH_VALUE;

  if ((ph_cnt < 1) || (ph_cnt > 2)) return PARSER_HASH_VALUE;

  bip39s->word_cnt = word_cnt;
  bip39s->ph_cnt = ph_cnt;

  return PARSER_OK;
}

static int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, void *digest_buf, salt_t *salt, void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, const int line_len)
{
  u32 *digest = (u32 *) digest_buf;
  bip39s_skeleton_t *bip39s = (bip39s_skeleton_t *) esalt_buf;

  bip39s->path_depth = 0;
  bip39s->target_type = BIP39_TARGET_IL_HEX;
  bip39s->word_cnt = 0;
  bip39s->ph_cnt = 0;
  bip39s->variant_slots = 1;

  memset (bip39s->path_indices, 0, sizeof (bip39s->path_indices));
  memset (bip39s->path_kind, 0, sizeof (bip39s->path_kind));
  bip39s->path_dynamic_count = 0;
  bip39s->dynamic_value_total = 0;
  bip39s->path_combo_total = 0ULL;
  memset (bip39s->dynamic_segments, 0, sizeof (bip39s->dynamic_segments));
  memset (bip39s->dynamic_values, 0, sizeof (bip39s->dynamic_values));
  memset (bip39s->target_hash, 0, sizeof (bip39s->target_hash));
  memset (bip39s->word_idx, 0, sizeof (bip39s->word_idx));

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt = 3;
  token.sep[0] = ':';
  token.sep[1] = ':';

  token.len_min[0] = 1;
  token.len_max[0] = sizeof (bip39s->skeleton) - 1;
  token.len_min[1] = 1;
  token.len_max[1] = sizeof (bip39s->address) - 1;
  token.len_min[2] = 1;
  token.len_max[2] = sizeof (bip39s->path) - 1;

  token.attr[0] = TOKEN_ATTR_VERIFY_LENGTH;
  token.attr[1] = TOKEN_ATTR_VERIFY_LENGTH;
  token.attr[2] = TOKEN_ATTR_VERIFY_LENGTH;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return rc_tokenizer;

  const u8 *skeleton_pos = token.buf[0];
  const u8 *address_pos = token.buf[1];
  const u8 *path_pos = token.buf[2];

  bip39s->skeleton_len = token.len[0];
  bip39s->address_len = token.len[1];
  bip39s->path_len = token.len[2];

  memset (bip39s->skeleton, 0, sizeof (bip39s->skeleton));
  memcpy (bip39s->skeleton, skeleton_pos, bip39s->skeleton_len);
  bip39s->skeleton[bip39s->skeleton_len] = 0;

  memset (bip39s->address, 0, sizeof (bip39s->address));
  memcpy (bip39s->address, address_pos, token.len[1]);
  bip39s->address[token.len[1]] = 0;

  memset (bip39s->path, 0, sizeof (bip39s->path));
  memcpy (bip39s->path, path_pos, token.len[2]);
  bip39s->path[token.len[2]] = 0;

  if (bip39s_parse_skeleton (skeleton_pos, bip39s->skeleton_len, bip39s) != PARSER_OK)
  {
    return PARSER_HASH_VALUE;
  }

  if (bip39_parse_derivation_path ((const char *) bip39s->path, bip39s->path_indices, bip39s->path_kind, bip39s->dynamic_segments, bip39s->dynamic_values, &bip39s->path_depth, &bip39s->path_dynamic_count, &bip39s->dynamic_value_total) == false)
  {
    return PARSER_HASH_VALUE;
  }

  const u64 combo_total = bip39_path_combo_total (bip39s->dynamic_segments, bip39s->path_dynamic_count);

  if (combo_total == 0) return (PARSER_HASH_VALUE);

  bip39s->path_combo_total = combo_total;

  // Two concatenated candidate words can split into valid word pairs in two ways, and each split
  // is a different mnemonic. The kernel covers both, so every candidate counts twice here.

  bip39s->variant_slots = (bip39s->ph_cnt == 2) ? 2 : 1;

  // The variant slots times the path combinations are the inner keyspace of a candidate, which is
  // what salt_iter means to the backend. It launches the loop kernel over windows of this count,
  // so autotune sees the real work and can pick a loop count for it.

  const u64 iter_total = combo_total * bip39s->variant_slots;

  if (iter_total > 0xffffffffULL)
  {
    return (PARSER_SALT_ITERATION);
  }

  salt->salt_iter = (u32) iter_total;
  salt->salt_iter2 = 0;

  const int rc_target = bip39_decode_target (address_pos, token.len[1], bip39s->target_hash, &bip39s->target_type, digest);

  if (rc_target != PARSER_OK) return rc_target;

  bip39s_set_salt_key (bip39s, salt);

  return PARSER_OK;
}

static int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, const int line_size)
{
  const bip39s_skeleton_t *bip39s = (const bip39s_skeleton_t *) esalt_buf;

  const int line_len = snprintf (line_buf, line_size, "%s:%s:%s",
                                 (const char *) bip39s->skeleton,
                                 (const char *) bip39s->address,
                                 (const char *) bip39s->path);

  return line_len;
}

static int module_hash_encode_status (const hashconfig_t *hashconfig, const void *digest_buf, const salt_t *salt, const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, const int line_size)
{
  int line_len = module_hash_encode (hashconfig, digest_buf, salt, esalt_buf, NULL, NULL, line_buf, line_size);

  if ((line_len < 0) || (line_len >= line_size))
  {
    return line_len;
  }

  const bip39s_skeleton_t *bip39s = (const bip39s_skeleton_t *) esalt_buf;

  if (bip39s == 0)
  {
    return line_len;
  }

  return bip39_append_combo_status (bip39s->path_combo_total, line_buf, line_size, line_len);
}

static u32         module_pw_max         (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return BIP39S_MAX_CANDIDATE_LEN;}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_esalt_size               = module_esalt_size;
  module_ctx->module_extra_tuningdb_block     = bip39_module_extra_tuningdb_block;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode_status       = module_hash_encode_status;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_kernel_accel_max         = bip39_module_kernel_accel_max;
  module_ctx->module_pw_max                   = module_pw_max;
  module_ctx->module_tmp_size                 = module_tmp_size;
}
