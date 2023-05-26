init_conda_dir=$(cd "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
source ${init_conda_dir}/defaults
source ${init_conda_dir}/env/create_conda_env
source ${init_conda_dir}/extra/populate_conda_env
source ${init_conda_dir}/rust/add_rust_to_env

activate_conda () {
    local env=${1:-$environment}

    # if not already in conda env, activate it
    if [ "$CONDA_PREFIX" = "" ] || [[ "$CONDA_PREFIX" != *"$env" ]]; then
        create_env $env
        populate_env $env
        init_rust $env

        conda_dir=$(conda info | grep -i 'base environment' | awk '{print $4}')
        source "$conda_dir/etc/profile.d/conda.sh"
        conda activate $env
    fi
    conda_activated=true
}

deactivate_conda () {
    if $conda_activated; then
        conda deactivate
    fi
}
