#!/bin/bash
# ******************
#  Copyright 2023 TekFive, Inc., Sean M. Brennan, and contributors
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

this_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
working_dir=$(pwd)

built=()
failed=()

# pdflatex runs -quiet, and a fatal error (a missing or unreadable image, say)
# leaves no PDF but still writes the .md, so the run looked fine. Say what
# happened. $1 is the out/ dir, $2 the document's base name, $3 a marker file
# touched before the build, so a PDF left over from an earlier run is not
# taken for this one.
check_pdf() {
    local out=$1 base=$2 marker=$3
    local pdf=$out/${base}.pdf log=$out/${base}.log
    if [[ -f $pdf && $pdf -nt $marker ]]; then
        built+=("$pdf")
        return 0
    fi
    failed+=("$pdf")
    echo "ERROR: no PDF produced for $base (expected $pdf)" >&2
    if [[ -f $log ]]; then
        # pdfTeX's fatal errors start with '!'; show each with the line after
        grep -A1 '^!' "$log" | grep -v '^--$' | sed 's/^/    /' >&2
        # an image named by the error that exists but is empty is the usual cause
        local img
        for img in $(grep -o '(file [^)]*)' "$log" | sed 's/(file \(.*\))/\1/' | sort -u); do
            if [[ -e $out/../$img && ! -s $out/../$img ]]; then
                echo "    $img is an empty file$( [[ -L $out/../$img ]] && echo " (symlink to $(readlink "$out/../$img"))" )" >&2
            fi
        done
        if grep -qs 'I found no \\bibdata' "$out/${base}.blg"; then
            echo "    (the bibliography is empty too: pdflatex stopped before \\bibliography)" >&2
        fi
        echo "    full log: $log" >&2
    else
        echo "    no log at $log: pdflatex did not run" >&2
    fi
    return 1
}

build_paper() {
    doc_dir=${this_dir}/$1
    source=$2
    bib=$3
    base=${source%.*}

    cd $doc_dir
    mkdir -p out
    local marker
    marker=$(mktemp)
    pdflatex -quiet -output-directory=out -aux-directory=out $source
    pdflatex -quiet -output-directory=out -aux-directory=out $source
    cd out
    bibtex -quiet -include-directory=.. $base
    cd ..
    pdflatex -quiet -output-directory=out -aux-directory=out $source
    pdflatex -quiet -output-directory=out -aux-directory=out $source
    check_pdf out "$base" "$marker"
    rm -f "$marker"

    echo "pandoc $source -o out/${base}.md --citeproc --bibliography $bib"
    pandoc -s $source -o out/${base}.md --citeproc --bibliography $bib
    pandoc -s $source -o out/${base}.md --citeproc --bibliography $bib
    cd $working_dir
}


doc_dir=${this_dir}/pitch
cd $doc_dir
mkdir -p out
marker=$(mktemp)
pdflatex --shell-escape -quiet HighTrustPitch.tex -output-directory=out -aux-directory=out
pdflatex --shell-escape -quiet HighTrustPitch.tex -output-directory=out -aux-directory=out
check_pdf out HighTrustPitch "$marker"
rm -f "$marker"
pandoc HighTrustPitch.tex -o out/HighTrustPitch.md
cd $working_dir

build_paper whitepaper HighTrust_DOD.tex HighTrust.bib

export AUTONOMOUSTRUST_SCENARIO=va
build_paper whitepaper HighTrust_VA.tex HighTrust.bib

echo
for pdf in "${built[@]}"; do
    echo "built  $pdf"
done
for pdf in "${failed[@]}"; do
    echo "FAILED $pdf" >&2
done
(( ${#failed[@]} == 0 ))
