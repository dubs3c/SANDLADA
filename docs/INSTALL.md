
# Installing SANDLÅDA

## Preparing the linux guest machine

SANDLÅDA was developed and tested with Ubuntu 18.04 "Bionic" and Virtualbox version 6.1.16 r140961. Support for Windows is still in development.

1. Download Ubuntu Bionic from here [https://releases.ubuntu.com/18.04.5/ubuntu-18.04.5-live-server-amd64.iso](https://releases.ubuntu.com/18.04.5/ubuntu-18.04.5-live-server-amd64.iso)
2. Configure the VM with at least 15 GB disk and 1 GB RAM
3. Once the virtual machine has been configured and installed, run the following installation script:

```bash
#!/bin/bash

##############
#  SANDLÅDA  #
### dubs3c ###

# Install dependencies
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys C8CAB6595FDFF622

codename=$(lsb_release -cs)
sudo tee /etc/apt/sources.list.d/ddebs.list << EOF
  deb http://ddebs.ubuntu.com/ ${codename}          main restricted universe multiverse
  #deb http://ddebs.ubuntu.com/ ${codename}-security main restricted universe multiverse
  deb http://ddebs.ubuntu.com/ ${codename}-updates  main restricted universe multiverse
  deb http://ddebs.ubuntu.com/ ${codename}-proposed main restricted universe multiverse
EOF

sudo apt-get update
sudo apt-get install linux-image-$(uname -r)-dbgsym python2.7 coreutils-dbgsym fakeroot build-essential crash kexec-tools makedumpfile kernel-wedge elfutils libdw-dev -y


# Install Systemtap
wget https://sourceware.org/systemtap/ftp/releases/systemtap-4.4.tar.gz
gunzip -d systemtap-4.4.tar.gz
tar -xf systemtap-4.4.tar
cd systemtap-4.4/
./configure
make
sudo make install

cd ..
rm -rf systemtap-4.4/

# Compile Systemtap script
wget https://raw.githubusercontent.com/cuckoosandbox/cuckoo/master/stuff/systemtap/strace.stp
sudo stap -p4 -r $(uname -r) strace.stp -m sandlada -v
sudo mv sandlada.ko /opt/

###############################
#         THE END             #
###############################
```

4. Transfer the `sandlada` executable to your guest VM
5. Set the agent to start on startup
```
$ crontab -e
@reboot /path/to/sandlada agent -s 192.168.1.25:9001 -lp 9001
```
6. Make custom changes (optional)
7. Create a config file in `~/.sandlada/config.ini` with the following contents:

```
# ======= General settings

[sandlada]
# Virtual Machine provider that will be used
provider=virtualbox

# ======= Virtual machine providers

[virtualbox]
# Run virtualbox in headless or gui mode
mode=headless
# Specify path to virtualbox. If empty, SANDLÅDA will assume VBOXManage is in path
path=
# Comma-separated list of VMs to be used for analysis. For each specified,
# you need to define a new VM section with necessary details
machines=dynlabs_default_1614027379469_65759

# ======= Analysis VMs

[SANDLADA_VM1]
# IP adress to agent, and port
ip=192.168.1.166:9001
# (optional) The machines UUID
uuid=43f997f0-0bd5-40f8-82a3-18c6ae4d69eb}
# Default snapshot to revert back to. If not specified
# SANDLÅDA will revert back to lastest snapshot
snapshot=
```

Analysis results will be stored in `~/.sandlada/result/<uuid>/`.

Assuming everything went fine, create a snapshot. Now you should have a good base VM for running dynamic malware analyses. The snapshot enures you can always revert back to a clean environment.

## Preparing the Windows guest machine
