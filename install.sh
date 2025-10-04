#!/bin/bash

echo instalando...

sudo apt update
sudo apt install -y build-essential clang llvm libelf-dev libbpf-dev libbpf-tools libjson-c-dev pkg-config python3-pip linux-headers-$(uname -r) linux-tools-$(uname -r) linux-cloud-tools-$(uname -r)

make all 2>/dev/null

if [[ $? -eq 0 ]];then
	echo -ne '\n\n\n\ninstalado, rode sudo ./daemon para iniciar\n'
else
	echo 'Erro na instalação'
fi

