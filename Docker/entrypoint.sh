#!/bin/bash
# Generate Axiom SSH keys at runtime if they don't exist
if [[ "${INSTALL_AXIOM}" == "true" ]] && [[ ! -f /root/.ssh/axiom_rsa ]]; then
    mkdir -p /root/.ssh /root/.axiom/configs
    ssh-keygen -b 4096 -t rsa -f /root/.ssh/axiom_rsa -q -N ""
    cat /root/.ssh/axiom_rsa.pub > /root/.axiom/configs/authorized_keys
fi

exec ./reconftw.sh "$@"
