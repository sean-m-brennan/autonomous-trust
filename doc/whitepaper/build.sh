#!/bin/bash
# ******************
#  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
# ******************
#
# Render the markdown whitepapers in this directory to branded PDFs, using
# doc/tekfive/tekfive.sty for layout (see tekfive-header.tex). With no
# arguments, builds all of them.
#
#   ./doc/whitepaper/build.sh                          # both papers
#   ./doc/whitepaper/build.sh doc/whitepaper/HighTrust.md
#
# Options are passed on the command line rather than through a pandoc defaults
# file, because -d path handling and relative-path resolution inside a defaults
# file both differ across pandoc versions.

set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
repo=$(cd "${here}/../.." &> /dev/null && pwd)

command -v pandoc > /dev/null || { echo "build.sh: pandoc not found in PATH" >&2; exit 1; }

# doc/tekfive/whitepaper/tekfive.sty is the package the .tex whitepapers load
# (a symlink to ../tekfive.sty); doc/tekfive/ is where the t5logo it includes
# lives. Both go on the search path.
export TEXINPUTS="${repo}/doc/tekfive/whitepaper:${repo}/doc/tekfive:${TEXINPUTS:-}"

# The documents number their own sections in the markdown, so no
# --number-sections here or every heading gets numbered twice. Margins, page
# furniture, and sidedness come from tekfive.sty, so no geometry variable
# either. Class options match HighTrust_DOD.tex, plus `table', which is how
# xcolor gets its table option (for \rowcolors) without an option clash
# against the template's own \usepackage{xcolor}.
opts=(
    --from=markdown
    --pdf-engine=pdflatex
    --include-in-header="${here}/tekfive-header.tex"
    --lua-filter="${here}/table-widths.lua"
    --variable=papersize:letter
    --variable=classoption:twoside
    --variable=classoption:table
    --variable=fontsize:10pt
    --variable=linestretch:1.05
    --variable=indent:false
)

sources=("$@")
if [ ${#sources[@]} -eq 0 ]; then
    sources=("${here}/AutonomousTrust.md" "${here}/HighTrust.md")
fi

cd "${repo}"
for source in "${sources[@]}"; do
    output="${source%.md}.pdf"
    echo "+ pandoc ${source} ${opts[*]} -o ${output}"
    pandoc "${source}" "${opts[@]}" -o "${output}"
done
