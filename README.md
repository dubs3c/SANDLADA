
# SANDLÅDA

**SANDLÅDA** is a dynamic malware analysis sandbox. It allows analysts to quickly and easily start analysing malware without caring about software dependencies or a gazillion configuration files. It's built in golang so it can easily be cross compiled to preferred platform and architecture.

**Features:**

* Static Analysis
    * Yara
    * Strings
    * Objdump
    * Readelf
* Behavior Analysis thanks to systemtap *(and cuckoo sandbox)*
* Network packet capturing

## How does it work?

You have two components, the collection server and the agent. The collection server runs on the host machine while the agent runs inside a virtual machine. Malware samples and necessary files are transferred to the VM via the collection server using HTTP. Once everything is in place, the agent will run the analysis by executing packet capturing, static analysis tools and finally the malware itself. All communication between agent and collection server is done via HTTP. Different VM providers have interfaces for directly communicating with VM, but it was decided to use HTTP and not care about what each individual VM provider offers.

As long as the agent and the collection server can communicate, you can run SANDLÅDA anywhere.

## Documentation

Full documentation can be found [here]().

## TODO

- [X] Linux guest support
- [X] Virtualbox support
- [ ] Windows guest support
- [ ] INetSim functionality
- [ ] Web interface
- [ ] Vmware ESXi support*
- [ ] QUEMU support*
- [ ] KVM support*
- [ ] Custom analysis tooling

* *This technically already works, but there is no support for starting, stopping or reverting the VM directly from SANDLÅDA*

## Motivation
SANDLÅDA *(Swedish for sandbox)* was built because I had so many different problems with cuckoo sandbox. Either it was a dependency problem or a software problem. The fact that it hasn't been upgraded to Python3 was a big motivator as well. I recently got very interested in malware analysis which gave me the idea to build my own sandbox :)

## Contributing
Any feedback or ideas are welcome! Want to improve something? Create a pull request!

1. Fork it!
2. Create your feature branch: `git checkout -b my-new-feature`
3. Configure pre commit checks: `pre-commit install`
4. Commit your changes: `git commit -am 'Add some feature'`
5. Push to the branch: `git push origin my-new-feature`
6. Submit a pull request :D

## License

SANDLÅDA is made with ♥ by [@dubs3c](https://github.com/dubs3c) and is released under the GPL 3 license.