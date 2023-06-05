"""
uk_dev_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)

export UK_WORKDIR=${uk_dev_dir}/.unikraft
export KRAFTRC=${uk_dev_dir}/.kraftrc

get_kraft () {
    # Find existing kraft tool
    local kraft=
    local kpath_alt=$(which -a kraft | tail -n +2 | head -1)
    local kpath_dflt=$(which kraft)
    if [ "$?" -eq "0" ]; then
        if [ "$tool" = "pykraft" ] && [[ "$kpath_dflt" = "$CONDA_PREFIX"* ]]; then
            kraft="$kpath_dflt"
        elif [ "$tool" = "kraftkit" ]; then
            if [[ "$kpath_dflt" != "$CONDA_PREFIX"* ]]; then
                kraft="$kpath_dflt"
            else
                kraft="$kpath_alt"
            fi
        fi
    fi

    # Install kraft, if missing
    if [ "$kraft" = "" ]; then
        if [ "$tool" = "pykraft" ]; then
            # install pykraft under conda
            pip3 install git+https://github.com/unikraft/pykraft.git
        elif [ "$tool" = "kraftkit" ]; then
            # install KraftKit
            curl --proto '=https' --tlsv1.2 -sSf https://get.kraftkit.sh | sh
        fi
        kraft=$(which kraft)
    fi

    echo $kraft
}
"""


def install_unikraft():
    pass
