# Helper functions for preparing UniKraft external libraries or fetching/building support sources

lib_src_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
lib_dir=$lib_src_dir/lib
extern_dir=$lib_src_dir/extern
source ${lib_src_dir}/get_kraft

config_ext_libs () {
    local defaults="$(cd ${lib_src_dir} && ls lib?*)"
    local lib_list=${1:-"$defaults"}
    local kraft=${2:-kraft}
    local cur_dir=$(pwd)

    mkdir -p $lib_dir
    for lib in $lib_list; do
        if [ ! -d ${lib_dir}/$lib ]; then
            echo "Initialize $lib"
            cd ${lib_dir} && $kraft lib init --no-prompt \
                --author-name "$(git config --list | grep "user\.name" | awk -F= '{print $2}')" \
                --author-email "$(git config --list | grep "user\.email" | awk -F= '{print $2}')" \
                --origin "$(cat ${lib_src_dir}/$lib/origin)" \
                --version "$(cat ${lib_src_dir}/$lib/version)" $lib
            rsync -a --exclude=version --exclude=origin ${this_src_dir}/$lib/ ${lib_dir}/$lib
            cd ${lib_dir}/$lib && git add ./* && git commit -a -m"Initial"
            rm -f ${lib_src_dir}/.update
            $kraft list add ${lib_dir}/$lib
        else
            synced=$(rsync -ai --exclude=version --exclude=origin ${lib_src_dir}/$lib/ ${lib_dir}/$lib)
            if [[ -n "$synced" ]]; then
                echo "Update $lib"
                cd ${lib_dir}/$lib && git add ./* && git commit -a -m"Update"
                cd ${UK_WORKDIR}/libs/$lib && git pull origin staging
                rm -f ${lib_src_dir}/.update
            fi
        fi
    done
    cd $cur_dir
}

get_ext_sources () {
    local impl=$1
    local cur_dir=$(pwd)
    mkdir -p $extern_dir
    mkdir -p ${lib_src_dir}/$impl/build

    for cfg_file in ${lib_src_dir}/$impl/extern_*.cfg; do
        source $cfg_file
        fetch_build $extern_dir ${lib_src_dir}/$impl/build
        cd $cur_dir
    done
}
