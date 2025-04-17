#!/bin/bash

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
