Vagrant.configure("2") do |config|
  config.vm.box = "bento/ubuntu-24.04"

  config.vm.provision "shell", inline: <<-SHELL
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y clang llvm libbpf-dev make gcc linux-headers-generic
    
    cd /vagrant
    make clean
    make
    sudo ./test_bpf ebpfdivert.bpf.o
  SHELL
end
