# Projeto acadêmico CodeShield  

Detector e interceptador de ramsonwares desenvolvido em C e C++ utilizando tecnologia eBPF e monitoramento de systemcalls contínuo.

 
 ## Instalação e Compilação
 
 ## Pré-requisitos
 - Ubuntu na última versão instalado.
 - Permissões de sudo para execução do script de instalação.
 - Ferramenta bpftool (caso a compilação falhe).
 
 ## Passos para Instalação
 
 1. Clone este repositório:
    ```bash
    git clone <url-do-repositorio>
    cd <nome-do-projeto>
    ```
 
 2. Execute o script de instalação:
 
    ```bash
    ./install.sh
    ```
 
 3. Caso a compilação falhe, baixe a última versão do bpftool em:
    https://github.com/libbpf/bpftool/releases
 
 4. Mova o executável do bpftool para a pasta do projeto.
 
 ## Ajustando o Makefile
 
 No arquivo Makefile, localize a seguinte linha:
 
    ```makefile
    syscall_monitor.skel.h: syscall_monitor.bpf.o
        /usr/lib/linux-tools-6.8.0-85/bpftool gen skeleton $< > $@
    ```
 
 Substitua por:
 
    ```makefile
    syscall_monitor.skel.h: syscall_monitor.bpf.o
        <caminho absoluto do bpftool> gen skeleton $< > $@
    ```
 
 ## Observações
 
 - Certifique-se de que o bpftool tenha permissão de execução:
 
    ```bash
    chmod +x bpftool
    ```
 
 - Após ajustar o Makefile, execute:
 
    ```bash
    make clean
    ```

    ```bash
    make all
    ```
 

