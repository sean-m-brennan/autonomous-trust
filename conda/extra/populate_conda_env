populate_conda_env_dir=$(cd "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
source ${populate_conda_env_dir}/../defaults

populate_env () {
    local env=${1:-$environment}
    local use_pip=${2:-false}
    local my_conda_base=$(cd "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)

    if [ "$use_pip" != "" ]; then
        pip install -r ${my_conda_base}/environment.recipes.txt
    else
        python_version=$(grep "\- python.*=" ${my_conda_base}/environment.yaml | awk -F"=" '{print $NF}' )
        for pkg in ${my_conda_base}/recipes/*; do
            prebuilt=false
            for arch in noarch $(conda run -n $env python3 ${my_conda_base}/getarch.py); do
                conda mambabuild --python ${python_version} $pkg
            done
        done
        #conda index $CONDA_PREFIX_1/conda-bld
        conda config --add channels local
        conda install -y -n $env -c local --file ${my_conda_base}/environment.recipes.txt
    fi
}
