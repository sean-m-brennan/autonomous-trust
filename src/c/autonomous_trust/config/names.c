/********************
 *  Copyright 2025 Sean M. Brennan and contributors
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 *******************/

#include <string.h>
#include <ctype.h>

#include <sodium.h>

#include "names.h"

static const char *adjectives[] = {
    "able", "alert", "ample", "apt", "avid", "azure", "bold", "brave", "brief",
    "bright", "brisk", "calm", "chief", "civil", "clean", "clear", "close",
    "cool", "crisp", "deft", "dense", "dry", "dual", "due", "eager", "early",
    "even", "exact", "fair", "fast", "fine", "firm", "fit", "flat", "fond",
    "free", "fresh", "full", "glad", "gold", "good", "grand", "gray", "great",
    "green", "grim", "half", "happy", "hard", "harsh", "high", "hot", "huge",
    "idle", "inner", "iron", "just", "keen", "kind", "known", "large", "last",
    "late", "lean", "left", "light", "live", "long", "lost", "loud", "low",
    "loyal", "lucky", "main", "major", "mild", "minor", "most", "near", "neat",
    "new", "next", "nice", "noble", "north", "novel", "odd", "old", "open",
    "outer", "pale", "past", "plain", "prime", "proud", "pure", "quick",
    "quiet", "rapid", "rare", "raw", "ready", "real", "red", "rich", "right",
    "rigid", "ripe", "rough", "round", "royal", "rural", "safe", "sharp",
    "sheer", "short", "shy", "slim", "slow", "smart", "smooth", "soft",
    "solid", "south", "spare", "stark", "steep", "stern", "still", "stout",
    "swift", "tall", "tame", "thick", "thin", "tight", "tiny", "top", "total",
    "tough", "true", "upper", "urban", "usual", "valid", "vast", "vivid",
    "vocal", "warm", "weak", "whole", "wide", "wild", "wise", "young"
};

static const char *nouns[] = {
    "ace", "acre", "aisle", "arch", "badge", "base", "bay", "beam", "blade",
    "blaze", "bloom", "bolt", "bond", "bone", "branch", "breeze", "bridge",
    "brook", "cairn", "cape", "cedar", "chain", "chalk", "charm", "chest",
    "chord", "claim", "cliff", "cloud", "coast", "coin", "coral", "core",
    "court", "craft", "crane", "creek", "crest", "cross", "crown", "dawn",
    "delta", "den", "dome", "dove", "drift", "drum", "dune", "eagle", "edge",
    "elm", "ember", "fern", "field", "flame", "flare", "fleet", "flint",
    "forge", "frost", "gate", "glade", "gleam", "glen", "globe", "grace",
    "grant", "grove", "guild", "haven", "hawk", "heath", "helm", "heron",
    "hill", "hive", "horn", "isle", "jade", "knoll", "lake", "lance", "lark",
    "leaf", "ledge", "light", "lily", "linden", "lodge", "loom", "lynx",
    "maple", "marsh", "mason", "mead", "mesa", "mill", "mist", "moss",
    "north", "oak", "opal", "orbit", "orca", "owl", "palm", "path", "peak",
    "pearl", "pier", "pine", "plume", "point", "pond", "port", "pulse",
    "quail", "quest", "rain", "range", "realm", "reed", "reef", "ridge",
    "ring", "river", "road", "robin", "rock", "rose", "sage", "sail", "shade",
    "shore", "slate", "slope", "spark", "spire", "spring", "spur", "star",
    "steel", "stone", "storm", "stream", "summit", "swift", "thorn", "tide",
    "tower", "trail", "vale", "vault", "verge", "vine", "vista", "warden",
    "wave", "well", "willow", "wind", "wing", "wood", "wren", "yard"
};

#define NUM_ADJECTIVES (sizeof(adjectives) / sizeof(adjectives[0]))
#define NUM_NOUNS (sizeof(nouns) / sizeof(nouns[0]))

int random_name(char *out, size_t out_len, char sep, bool capitalize)
{
    if (out == NULL || out_len < 4)
        return -1;

    uint32_t a_idx = randombytes_uniform((uint32_t)NUM_ADJECTIVES);
    uint32_t n_idx = randombytes_uniform((uint32_t)NUM_NOUNS);

    const char *adj = adjectives[a_idx];
    const char *noun = nouns[n_idx];

    char adj_buf[64];
    char noun_buf[64];
    strncpy(adj_buf, adj, sizeof(adj_buf) - 1);
    adj_buf[sizeof(adj_buf) - 1] = '\0';
    strncpy(noun_buf, noun, sizeof(noun_buf) - 1);
    noun_buf[sizeof(noun_buf) - 1] = '\0';

    if (capitalize)
    {
        adj_buf[0] = (char)toupper((unsigned char)adj_buf[0]);
        noun_buf[0] = (char)toupper((unsigned char)noun_buf[0]);
    }

    int written = snprintf(out, out_len, "%s%c%s", adj_buf, sep, noun_buf);
    if (written < 0 || (size_t)written >= out_len)
        return -1;
    return 0;
}
