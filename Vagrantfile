# -*- mode: ruby -*-
# vi: set ft=ruby :

# All Vagrant configuration is done below. The "2" in Vagrant.configure
# configures the configuration version (we support older styles for
# backwards compatibility). Please don't change it unless you know what
# you're doing.
Vagrant.configure("2") do |config|
  config.vm.box = "pwn/PoorOperationalSec"
  config.ssh.private_key_path="~/.ssh/id_rsa_vagrant"
  config.vm.box_version = "1.0.1"
  config.vm.provision :shell, inline: "cd ~/PoorOperationalSecurityPractices && python ./pooropssec.py", run: 'always', privileged: false
end
