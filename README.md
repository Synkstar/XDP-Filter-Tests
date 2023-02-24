## XDP Filter tests
A basic stateless xdp program that does ratelimiting and has filtering for common reflection attacks including dns and ntp reflection.
This was something I did to mess around and thought it could be a good learning resource for someone interested in learning how to do ratelimiting etc.

### Compiling and installing the program
```bash
# Install dependencies
sudo apt install build-essential make clang llvm m4 libpcap-dev libelf-dev gcc-multilib cmake

# Clone the repo and its submodules
git clone https://github.com/Synkstar/XDP-Filter-Tests/xdp-filter-tests.git --recursive

# Change to the projects directory
cd xdp-filter-tests

# Compile the program
make

# Install the program
make install
```

### Running the program.
This program also creates a service file that you could use but I doubt anyone would want to use this program on a production system.
```bash
# Start command
xdpfilterstest -i {interface}
```
