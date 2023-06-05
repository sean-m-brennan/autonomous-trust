# Helper function for applying patches to UniKraft

patch_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
source ${patch_dir}/../get_kraft

apply_uk_patches () {
    impl=$1

    if [ ! -e $UK_WORKDIR/.patched ]; then
        echo "Patch unikraft"
        cd $UK_WORKDIR && patch -p1 --forward < $patch_dir/unikraft.patch
        if [ -e $patch_dir/unikraft.patch.$impl ]; then
            cd $UK_WORKDIR && patch -p1 --forward < $patch_dir/unikraft.patch.$impl
        fi
        # Cannot create a patch with patches in it, so copy instead
        cd $patch_dir
        for patch_info in ${impl}_patch_*_*; do
            lib_dir=${patch_info#${impl}_patch_}
            lib_dir=${lib_dir%_*}
            patch_file=${patch_info##*_}
            cp $patch_info ${UK_WORKDIR}/libs/$lib_dir/patches/$patch_file
        done
        touch $UK_WORKDIR/.patched
    fi
}
