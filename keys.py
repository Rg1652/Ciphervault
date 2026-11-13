"""
CipherVault Key & Password Studio
Provides cryptographically secure password generation, Diceware passphrases,
keyfile creation, and detailed password strength/entropy calculation.
"""

import math
import secrets
import string
import os
from typing import Dict, Any, Tuple

# Curated list of high-memorability words for Diceware passphrase generation
WORDLIST = [
    "absorb", "accent", "acid", "acorn", "action", "active", "actor", "admire", "advance", "aerial",
    "affair", "afford", "agency", "agent", "agile", "agree", "ahead", "aim", "alarm", "album",
    "alert", "alien", "align", "alike", "alive", "alpha", "alpine", "altar", "amber", "amend",
    "anchor", "ancient", "angel", "angle", "animal", "anthem", "apex", "apron", "aquatic", "arcade",
    "arctic", "arena", "armor", "arrow", "artist", "aspect", "assure", "atlas", "atom", "atomic",
    "attach", "attic", "audio", "audit", "aurora", "author", "auto", "autumn", "avatar", "avenue",
    "avocado", "axis", "azure", "bacon", "badge", "baker", "balance", "balcony", "ballot", "bamboo",
    "banana", "banner", "barber", "barely", "bargain", "barrel", "barrier", "basalt", "base", "basic",
    "basket", "battle", "beacon", "beam", "beauty", "begin", "behalf", "belief", "belong", "bench",
    "benefit", "berry", "beyond", "bicycle", "binary", "biology", "birch", "bison", "bitter", "blade",
    "blame", "blanket", "blast", "blaze", "blend", "bless", "blind", "bliss", "block", "bloom",
    "blossom", "board", "boat", "bold", "bonus", "border", "botany", "bounce", "bounty", "bracket",
    "brave", "breeze", "brick", "bridge", "bright", "bronze", "bubble", "budget", "buffalo", "bullet",
    "bundle", "bunker", "burst", "cabin", "cactus", "cadence", "calm", "camera", "camp", "canary",
    "canyon", "canvas", "captain", "caravan", "carbon", "cargo", "carrier", "cascade", "castle", "cat",
    "cattle", "cavern", "cedar", "ceiling", "center", "ceramic", "cereal", "champion", "channel", "chaos",
    "chapter", "charcoal", "charge", "chariot", "charm", "charter", "chase", "cheerful", "cheetah", "chemist",
    "cherry", "chess", "chrome", "chronic", "circuit", "citizen", "citrus", "civic", "clarity", "classic",
    "clever", "cliff", "climate", "climb", "clinic", "clock", "clone", "cloud", "clover", "cluster",
    "coastal", "cobalt", "coffee", "cohort", "column", "combat", "comedy", "comet", "comfort", "command",
    "compact", "compass", "complex", "concept", "concord", "condor", "connect", "conquer", "console", "constant",
    "copper", "coral", "corner", "cosmos", "cotton", "couch", "counsel", "courage", "cousin", "cove",
    "cradle", "craft", "crane", "crater", "crayon", "creek", "crest", "cricket", "crimson", "crisis",
    "critic", "cross", "crown", "crucial", "cruise", "crystal", "cube", "cubic", "culture", "curious",
    "current", "curve", "custom", "cyber", "cycle", "cynic", "dagger", "daily", "dairy", "damage",
    "dancer", "daring", "darwin", "dawn", "daylight", "dazzle", "deal", "debris", "decade", "decimal",
    "deck", "decode", "decor", "decoy", "defence", "delta", "deluxe", "demand", "demise", "density",
    "dental", "depot", "depth", "deputy", "derby", "desert", "design", "desk", "desire", "destiny",
    "detail", "detect", "device", "devote", "dialog", "diamond", "diesel", "digital", "dilemma", "diploma",
    "direct", "disc", "domain", "domino", "donkey", "dragon", "drain", "drastic", "draw", "dream",
    "drift", "drill", "drone", "drum", "dryer", "duck", "duet", "dune", "durable", "dynamic",
    "eager", "eagle", "early", "earth", "easel", "echo", "eclipse", "economy", "edge", "editor",
    "effort", "electric", "element", "elite", "elm", "ember", "emerald", "empire", "enable", "enchant",
    "energy", "engine", "enigma", "enjoy", "enrich", "ensemble", "entity", "entry", "envoy", "epic",
    "episode", "epoch", "equal", "equip", "erase", "escape", "escort", "essay", "essence", "estate",
    "eternal", "ethics", "eureka", "event", "everest", "exact", "exotic", "expand", "expert", "export",
    "fabric", "facade", "facet", "factor", "falcon", "fame", "fancy", "fantasy", "farmland", "fast",
    "fathom", "feather", "federal", "fellow", "fence", "fender", "ferry", "festive", "fiber", "fiction",
    "fiesta", "fighter", "figure", "filter", "final", "finance", "finch", "finder", "firefly", "firm",
    "fitness", "flame", "flank", "flare", "flask", "flavor", "fleet", "flight", "flora", "flourish",
    "flower", "fluent", "flux", "focus", "fog", "foil", "foliage", "force", "forest", "forge",
    "formula", "fortress", "fortune", "forum", "fossil", "foster", "foundry", "fox", "fraction", "fragment",
    "freedom", "freeze", "friction", "frigate", "frontier", "frost", "fruit", "fuel", "fugitive", "funnel",
    "fusion", "future", "gadget", "galaxy", "galley", "galvanic", "gargoyle", "garnet", "gasoline", "gateway",
    "gather", "gauge", "gazelle", "gear", "gemini", "general", "genesis", "genius", "gentle", "genuine",
    "geology", "geyser", "ghost", "giant", "glacier", "glade", "glamour", "glance", "glass", "glide",
    "glimmer", "glimpse", "globe", "glory", "glow", "goblet", "gold", "gondola", "gospel", "govern",
    "grace", "gradient", "grain", "grand", "granite", "grape", "graph", "gravity", "grizzly", "grove",
    "guardian", "guitar", "gulf", "gust", "gyro", "habitat", "halo", "hammer", "harbor", "hardy",
    "harmony", "harpoon", "harvest", "haven", "hawk", "hazard", "headland", "healing", "heaven", "hedgehog",
    "helium", "helmet", "herald", "herb", "heritage", "heroic", "hexagon", "hideaway", "highland", "highway",
    "history", "hockey", "holiday", "hollow", "homeland", "honey", "horizon", "horn", "hornet", "horseshoe",
    "host", "hotline", "hound", "hover", "hub", "humble", "hunter", "hurdle", "hurricane", "hybrid",
    "hydra", "hydrogen", "hyena", "hyper", "iceberg", "icon", "idea", "identify", "iguana", "illusion",
    "image", "impact", "imperial", "import", "impulse", "incense", "index", "indigo", "infinite", "ingress",
    "initial", "inlet", "insight", "inspire", "instant", "integer", "integral", "intel", "intend", "intense",
    "interior", "invent", "inverse", "island", "isotope", "ivory", "jacket", "jaguar", "javelin", "jazz",
    "jewel", "jigsaw", "jockey", "journey", "jovial", "jubilee", "judge", "jumbo", "jungle", "jupiter",
    "jury", "justice", "kaleido", "kangaroo", "karat", "katana", "kayak", "keeper", "kelp", "kennel",
    "kernel", "kestrel", "keynote", "kick", "kinetic", "kingdom", "kiosk", "kite", "kitten", "knight",
    "kobold", "kodiak", "kraken", "krypton", "label", "labor", "ladder", "lagoon", "lantern", "laptop",
    "lark", "laser", "latitude", "laurel", "lava", "lawful", "leader", "leaf", "league", "ledger",
    "legacy", "legend", "lemon", "leopard", "level", "lever", "liberty", "library", "lichen", "lifeboat",
    "light", "limelight", "limit", "linear", "linen", "lingo", "lion", "liquid", "list", "lithium",
    "lizard", "llama", "lobby", "lobster", "locate", "lock", "locus", "logic", "logistics", "lotus",
    "lounge", "loyalty", "lucid", "luggage", "lumber", "lunar", "luxury", "lyric", "macro", "magenta",
    "magic", "magma", "magnet", "magnitude", "magnolia", "magpie", "mahogany", "maiden", "majesty", "mammoth",
    "mandate", "mango", "manifest", "manor", "mantis", "maple", "marathon", "marble", "marine", "mariner",
    "market", "marmot", "marshal", "martini", "marvel", "mascot", "mason", "master", "matrix", "maximum",
    "meadow", "mechanic", "medal", "median", "medium", "melody", "memory", "mentor", "mercury", "meridian",
    "merit", "meteor", "metric", "micro", "midnight", "milestone", "mineral", "minotaur", "miracle", "mirage",
    "mirror", "missile", "mission", "mist", "mixture", "mobile", "model", "modem", "modern", "modular",
    "momentum", "monarch", "monitor", "monkey", "monolith", "monsoon", "moonlight", "mosaic", "motion", "motive",
    "mountain", "muse", "mustang", "mutation", "mystery", "mystic", "myth", "nadal", "nanotech", "narrator",
    "native", "natural", "nautilus", "navajo", "navigate", "nebula", "nectar", "nemesis", "neon", "nerve",
    "nest", "network", "neutral", "newton", "nexus", "nickel", "night", "nimble", "ninja", "nitrogen",
    "noble", "nomad", "nordic", "normal", "north", "nostalgia", "notable", "notice", "nova", "novel",
    "nucleus", "nugget", "number", "numerical", "nurture", "oak", "oasis", "object", "observe", "obsidian",
    "ocean", "octagon", "octave", "octane", "odyssey", "olympic", "omega", "omen", "omnibus", "onyx",
    "opal", "open", "opera", "optics", "optimal", "oracle", "orange", "orbit", "orchard", "orchid",
    "order", "organ", "orient", "origin", "orion", "ornament", "oscar", "outback", "outlaw", "outlook",
    "outpost", "oval", "overland", "overture", "oxygen", "ozone", "pacific", "pack", "packet", "pageant",
    "palace", "palette", "palm", "panther", "papyrus", "paradox", "parallel", "paramount", "parchment", "parent",
    "park", "parrot", "passage", "passport", "pastor", "patent", "path", "patient", "patriot", "patrol",
    "pattern", "pavilion", "peace", "peak", "pebble", "pedal", "pelican", "pendulum", "penguin", "pennant",
    "pentagon", "pepper", "percent", "perch", "perfect", "perform", "peridot", "peril", "perk", "permit",
    "petal", "phantom", "pharmacy", "phase", "phoenix", "photon", "physics", "piano", "picket", "pilot",
    "pinnacle", "pioneer", "pipeline", "pistol", "piston", "pitch", "pivot", "pixel", "planet", "plasma",
    "plateau", "platinum", "plaza", "plenty", "plover", "plow", "plum", "plunge", "plural", "polar",
    "policy", "polaris", "polymer", "ponder", "pontoon", "porcelain", "portal", "portrait", "positron", "pottery",
    "power", "prairie", "precision", "predator", "premier", "premium", "prestige", "prevail", "prey", "pride",
    "primate", "prime", "primitive", "prism", "pristine", "private", "prodigy", "profile", "profound", "program",
    "project", "prologue", "promenade", "promise", "prophet", "protect", "proton", "protocol", "proud", "proverb",
    "province", "prowler", "prudent", "pulse", "puma", "pumpkin", "pupil", "purchase", "pure", "pyramid",
    "python", "quaint", "quake", "quality", "quantum", "quarry", "quartz", "quasar", "queen", "quest",
    "quick", "quiver", "quota", "radar", "radiant", "radius", "raft", "railway", "rainbow", "rampart",
    "rancher", "ranger", "rapid", "raptor", "rare", "ravine", "ray", "reactor", "realm", "rebel",
    "rebound", "recipe", "reckon", "reclaim", "record", "recover", "redwood", "reef", "reflect", "reflex",
    "reform", "refuge", "regal", "regent", "regime", "region", "regular", "reign", "relic", "relief",
    "remedy", "remnant", "render", "renew", "renown", "repair", "republic", "rescue", "reservoir", "reset",
    "resident", "resolve", "resort", "resource", "response", "restore", "reveal", "reverse", "revival", "reward",
    "rhino", "rhythm", "ribbon", "ridge", "rifle", "rigor", "ripple", "ritual", "river", "roadway",
    "roast", "robot", "robust", "rocket", "rocky", "rogue", "roller", "romance", "rooster", "rotate",
    "rouge", "rover", "royal", "ruby", "rudder", "runner", "runway", "rural", "saber", "saddle",
    "safari", "saffron", "sailor", "saint", "saloon", "sample", "sanctuary", "sandstone", "sapphire", "satchel",
    "satellite", "satin", "saturate", "saturn", "savage", "saving", "savior", "scalar", "scale", "scanner",
    "scenic", "scepter", "scholar", "science", "scooter", "scope", "scout", "screen", "script", "sculptor",
    "seagull", "seal", "search", "season", "secure", "sediment", "segment", "sensor", "sentinel", "sequoia",
    "serenade", "serene", "sergeant", "serpent", "service", "shadow", "shimmer", "shipyard", "signal", "silicon",
    "silver", "simple", "siren", "skater", "skipper", "skyline", "slate", "sled", "sleek", "slide",
    "slingshot", "solar", "solace", "solid", "solstice", "solution", "sonar", "sonic", "source", "sovereign",
    "spark", "spectrum", "sphere", "sphinx", "spider", "spiral", "spirit", "splash", "splendid", "sponsor",
    "spring", "sprint", "sprout", "squad", "square", "stadium", "starlight", "statue", "stealth", "stellar",
    "steppe", "sterling", "strata", "stream", "strike", "stride", "sublime", "summit", "sunburst", "supernova",
    "supreme", "surgeon", "survival", "swan", "swift", "sword", "symbol", "symmetry", "symphony", "synapse",
    "synergy", "syntax", "system", "tactical", "talon", "tandem", "target", "tariff", "tavern", "telescope",
    "template", "temple", "temporal", "tenacity", "terminal", "terrain", "testament", "tetra", "texture", "theater",
    "thermal", "thesis", "thrill", "throne", "thunder", "tide", "tiger", "timber", "titan", "toast",
    "token", "topaz", "tornado", "torpedo", "totem", "tower", "trace", "tractor", "trader", "traffic",
    "trail", "trance", "transit", "treasure", "trench", "tribute", "trident", "trigger", "triumph", "trooper",
    "trophy", "tropical", "truck", "trumpet", "tsunami", "tulip", "tundra", "tunnel", "turbine", "turret",
    "turtle", "twilight", "tycoon", "typhoon", "ultimate", "umbra", "umbrella", "underdog", "unicorn", "union",
    "unique", "universe", "upbeat", "upgrade", "uphold", "upland", "uprising", "uranium", "urban", "urgent",
    "utopia", "valiant", "valley", "valor", "valve", "vanguard", "vanilla", "vapor", "vault", "vector",
    "velocity", "velvet", "venture", "venus", "verdict", "vertex", "vertical", "vessel", "veteran", "vibrant",
    "viceroy", "victor", "victory", "vintage", "violet", "violin", "viper", "virtue", "vision", "visitor",
    "visual", "vital", "vivid", "vocal", "volcano", "vortex", "voyage", "vulcan", "vulture", "wagon",
    "walnut", "wanderer", "warrior", "watchman", "waterfall", "wave", "weapon", "weasel", "weather", "webmaster",
    "whistle", "wildcat", "willow", "windfall", "window", "winter", "wisdom", "wizard", "wolf", "wolverine",
    "wonder", "woodland", "workshop", "world", "worship", "wren", "wrist", "yacht", "yearbook", "yellow",
    "yield", "yosemite", "young", "youth", "yucca", "zenith", "zephyr", "zero", "zigzag", "zodiac"
]


def generate_complex_password(
    length: int = 24,
    use_upper: bool = True,
    use_lower: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True
) -> str:
    """Generate a high-entropy random password using CSPRNG."""
    charset = ""
    guaranteed = []

    if use_upper:
        charset += string.ascii_uppercase
        guaranteed.append(secrets.choice(string.ascii_uppercase))
    if use_lower:
        charset += string.ascii_lowercase
        guaranteed.append(secrets.choice(string.ascii_lowercase))
    if use_digits:
        charset += string.digits
        guaranteed.append(secrets.choice(string.digits))
    if use_symbols:
        symbols = "!@#$%^&*()-_=+[]{}|;:,.<>?"
        charset += symbols
        guaranteed.append(secrets.choice(symbols))

    if not charset:
        charset = string.ascii_letters + string.digits
        guaranteed.append(secrets.choice(charset))

    needed = max(0, length - len(guaranteed))
    rest = [secrets.choice(charset) for _ in range(needed)]
    all_chars = guaranteed + rest

    # Secure shuffle
    for i in range(len(all_chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        all_chars[i], all_chars[j] = all_chars[j], all_chars[i]

    return "".join(all_chars)


def generate_passphrase(num_words: int = 5, separator: str = "-") -> str:
    """Generate a memorable Diceware-style passphrase using CSPRNG."""
    chosen = [secrets.choice(WORDLIST) for _ in range(num_words)]
    return separator.join(chosen)


def generate_hex_key(num_bytes: int = 32) -> str:
    """Generate a 256-bit (or custom) cryptographic hex key."""
    return secrets.token_hex(num_bytes)


def generate_keyfile(file_path: str, num_bytes: int = 64) -> str:
    """Generate a physical cryptographic keyfile (.key) with 512 bits of entropy."""
    key_bytes = os.urandom(num_bytes)
    hex_repr = key_bytes.hex()

    content = (
        "-----BEGIN CIPHERVAULT ENCRYPTION KEYFILE-----\n"
        f"Length: {num_bytes * 8} bits\n"
        f"Key: {hex_repr}\n"
        "-----END CIPHERVAULT ENCRYPTION KEYFILE-----\n"
    )

    with open(file_path, "w", encoding="utf-8") as f:
        f.write(content)

    return hex_repr


def evaluate_password_strength(password: str) -> Dict[str, Any]:
    """
    Evaluate password strength, entropy in bits, crack time, and visual metrics.
    Returns:
        dict with: score (0-100), label, color, entropy_bits, crack_time_str
    """
    if not password:
        return {
            "score": 0,
            "label": "Empty",
            "color": "#64748B",
            "entropy_bits": 0.0,
            "crack_time_str": "Instant",
            "description": "Please enter a password."
        }

    length = len(password)
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(not c.isalnum() for c in password)

    pool_size = 0
    if has_lower:
        pool_size += 26
    if has_upper:
        pool_size += 26
    if has_digit:
        pool_size += 10
    if has_symbol:
        pool_size += 32

    if pool_size == 0:
        pool_size = 1

    # Shannon Entropy = L * log2(pool_size)
    entropy = length * math.log2(pool_size)

    # Estimate crack time assuming an adversary with a 100 billion guesses/sec GPU cluster (10^11 ops/sec)
    # With Argon2id / PBKDF2 it's even billions of times slower, but we use raw search space for standard rating
    guesses = 2 ** entropy
    rate = 1e11  # 100 Billion keys/sec
    seconds = guesses / (2 * rate)

    if seconds < 1:
        crack_time = "Milliseconds"
    elif seconds < 60:
        crack_time = f"{int(seconds)} Seconds"
    elif seconds < 3600:
        crack_time = f"{int(seconds / 60)} Minutes"
    elif seconds < 86400:
        crack_time = f"{int(seconds / 3600)} Hours"
    elif seconds < 31536000:
        crack_time = f"{int(seconds / 86400)} Days"
    elif seconds < 31536000 * 1000:
        crack_time = f"{int(seconds / 31536000)} Years"
    elif seconds < 31536000 * 1e6:
        crack_time = f"{int(seconds / (31536000 * 1000)):,} Millennia"
    else:
        crack_time = "Trillions of Years (Uncrackable)"

    # Compute 0-100 score
    if entropy < 30:
        score = min(25, int(entropy * 0.8))
        label = "Very Weak"
        color = "#EF4444"  # Red
        desc = "Extremely vulnerable to dictionary & brute-force attacks."
    elif entropy < 50:
        score = 25 + int((entropy - 30) * 1.25)
        label = "Weak"
        color = "#F97316"  # Orange
        desc = "Vulnerable to high-speed offline cracking."
    elif entropy < 70:
        score = 50 + int((entropy - 50) * 1.0)
        label = "Moderate"
        color = "#EAB308"  # Yellow/Amber
        desc = "Decent protection, but could be stronger."
    elif entropy < 90:
        score = 70 + int((entropy - 70) * 1.0)
        label = "Strong"
        color = "#10B981"  # Emerald Green
        desc = "Excellent protection against modern brute-force clusters."
    else:
        score = min(100, 90 + int((entropy - 90) * 0.5))
        label = "Military-Grade"
        color = "#06B6D4"  # Cyan
        desc = "Immense cryptographic security. Computationally unfeasible to crack."

    return {
        "score": score,
        "label": label,
        "color": color,
        "entropy_bits": round(entropy, 1),
        "crack_time_str": crack_time,
        "description": desc
    }
