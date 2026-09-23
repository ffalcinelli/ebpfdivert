# -*- mode: ruby -*-
# vi: set ft=ruby :
#
# Test VMs.  Bring up one at a time and destroy it when done:
#
#   vagrant up default && vagrant ssh default -c "cd /vagrant && make clean && make && \
#     ./test_filter && sudo ./test_bpf ebpfdivert.bpf.o && sudo ./tests/run_integration_tests.sh"
#   vagrant destroy -f default
#
# "default" is Ubuntu 24.04 (kernel 6.8, TCX links); "legacy" is Ubuntu 22.04
# (kernel 5.15, classic cls_bpf attachment and the stale-handle reaper).

PROVISION = <<-SHELL
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y clang llvm make gcc pkg-config libelf-dev zlib1g-dev ethtool iproute2
SHELL

Vagrant.configure("2") do |config|
  config.vm.provider "virtualbox" do |vb|
    vb.memory = "2048"
    vb.cpus = 2
  end

  config.vm.define "default", primary: true do |m|
    m.vm.box = "bento/ubuntu-24.04"
    m.vm.hostname = "ebpfdivert"
    m.vm.provision "shell", inline: PROVISION
  end

  config.vm.define "legacy", autostart: false do |m|
    m.vm.box = "bento/ubuntu-22.04"
    m.vm.hostname = "ebpfdivert-legacy"
    m.vm.provision "shell", inline: PROVISION
  end
end
