#!/bin/bash
# ******************
#  Copyright 2025 Sean M. Brennan and contributors
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

build_paper() {
    doc_dir=${this_dir}/$1
    source=$2
    bib=$3
    base=${source%.*}

    cd $doc_dir
    pdflatex -quiet -output-directory=out -aux-directory=out $source
    pdflatex -quiet -output-directory=out -aux-directory=out $source
    cd out
    bibtex -quiet -include-directory=.. $base
    cd ..
    pdflatex -quiet -output-directory=out -aux-directory=out $source
    pdflatex -quiet -output-directory=out -aux-directory=out $source

    echo "pandoc $source -o out/${base}.md --citeproc --bibliography $bib"
    pandoc -s $source -o out/${base}.md --citeproc --bibliography $bib
    pandoc -s $source -o out/${base}.md --citeproc --bibliography $bib
    cd $working_dir
}


doc_dir=${this_dir}/pitch
cd $doc_dir
pdflatex --shell-escape -quiet HighTrustPitch.tex -output-directory=out -aux-directory=out
pdflatex --shell-escape -quiet HighTrustPitch.tex -output-directory=out -aux-directory=out
pandoc HighTrustPitch.tex -o out/HighTrustPitch.md
cd $working_dir

build_paper whitepaper HighTrust_DOD.tex HighTrust.bib

export AUTONOMOUSTRUST_SCENARIO=va
build_paper whitepaper HighTrust_VA.tex HighTrust.bib
