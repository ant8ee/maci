#!/usr/bin/env bash

VERSION=0.1
WORK_DIR=$(cd $(dirname $0); pwd)

function build_module() {
    m_name=$1
    m_subdir=$2
    m_dir=${WORK_DIR}/${m_subdir}/${m_name}
    echo "build module ${m_dir}"
    cd ${m_dir}
    cargo +nightly contract build
    if [ $? -ne 0 ];then
      echo "build module failed"
      exit 1
    fi
    echo "copy to ../release"
    cp -f ${m_dir}/target/ink/${m_name}.wasm ${WORK_DIR}//release/${m_name}_v$VERSION.wasm
    cp -f ${m_dir}/target/ink/${m_name}.contract ${WORK_DIR}//release/${m_name}_v$VERSION.contract
    cp -f ${m_dir}/target/ink/metadata.json ${WORK_DIR}//release/${m_name}_v$VERSION.json
    cd -
}

function format_module() {
    m_name=$1
    m_dir=${WORK_DIR}/${m_name}
    echo "format module ${m_dir}"
    cd ${m_dir}
    cargo fmt
    if [ $? -ne 0 ];then
      echo "format module  ${m_dir} failed"
      exit 1
    fi
    cd -
}


function copy_abi(){
     basepath=$(pwd)
            srcpath=release
            destpath=../../zkp/maci_dot/contracts/ts/abi
            cp -f ${basepath}/${srcpath}/*.json ${basepath}/${destpath} 
}

case $1 in
        b)
          echo "build module "
            build_module maci
            build_module versatile_verifier
            build_module signup_token
            build_module contracts_manager
            build_module free_for_all_signup_gatekeeper gatekeepers
            build_module signup_token_gatekeeper gatekeepers
            build_module constant_initial_voice_credit_proxy initial_voice_credit_proxy
            build_module user_defined_initial_voice_credit_proxy initial_voice_credit_proxy
        ;;
        f)
          echo "format code"
            format_module maci
            format_module versatile_verifier
            format_module signup_token
            format_module contracts_manager
            format_module gatekeepers/free_for_all_signup_gatekeeper
            format_module gatekeepers/signup_token_gatekeeper
            format_module initial_voice_credit_proxy/constant_initial_voice_credit_proxy
            format_module initial_voice_credit_proxy/user_defined_initial_voice_credit_proxy
        ;;
        c)
          echo "copy abi"
          copy_abi
        ;;
        *)
          echo "b--build module f--format code  c--copy abi"
        ;;
esac