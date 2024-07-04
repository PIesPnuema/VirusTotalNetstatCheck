# VirusTotal Netstat Check

## Description

This script automates the process of checking current established network connections against VirusTotal to identify any potentially suspicious connections. Designed for Windows users utilizing WSL as their primary command-line interface, it captures network connections, processes them, and verifies them against VirusTotal.

## Features

- Captures current established network connections using `netstat`.
- Filters and processes the connections to extract remote IP addresses.
- Checks each IP address against VirusTotal to identify any suspicious activity.
- Compiles and runs a C++ program to handle the VirusTotal API requests.

## Dependencies

Ensure the following dependencies are installed on your system:

- `curl`
- `g++`
- `libssl-dev`
- `nlohmann-json-dev`

## Installation

### Clone the Repository

First, clone the repository to the specified location:

```sh
git clone https://github.com/yourusername/VirusTotalNetstatCheck.git ~/.local/bin/Scripts/VirusTotalNetstatCheck
```

### Set Up PATH

Add the script directory to your `PATH` by including the following lines in your `.bashrc`, `.zshrc`, or relevant shell configuration file:

```sh
# set PATH to include Scripts repo
if [ -d "$HOME/.local/bin/Scripts/VirusTotalNetstatCheck" ]; then
    PATH="$HOME/.local/bin/Scripts/VirusTotalNetstatCheck:$PATH"
fi
```

After adding the above lines, reload your shell configuration:

```sh
source ~/.bashrc  # or source ~/.zshrc
```

## Setup API Key
You need to create an account with VirusTotal to receive an API key. 

Create a file named `apikey.txt` in the same directory (`~/.local/bin/Scripts/VirusTotalNetstatCheck`) and place your VirusTotal API key in it. ***Ensure the file contains nothing but the API key.***

## Usage

### Running the Script

To run the script, navigate to the project directory and execute the script:

```sh
cd ~/.local/bin/Scripts/VirusTotalNetstatCheck
./virusTotalNetstatCheck
```

If you successfully added the script to your `$PATH`, you can run the script using its name as a global command. Since the name is long, you can also create an alias to shorten it for convenience:

```sh
alias vtcheck='virusTotalNetstatCheck'
```

Add this line to your `.bashrc` or `.zshrc` file to make the alias persistent:

```sh
echo "alias vtcheck='virusTotalNetstatCheck'" >> ~/.bash_aliases  # or ~/.zshrc ~/.bashrc
source ~/.bash_aliases  # or source ~/.zshrc ~/.bashrc
```

Now you can run the script using the `vtcheck` command.
### Script Details

1. **Capturing Network Connections**:
    - The script uses PowerShell to capture the current established network connections and saves the output to `NetstatRawOutput.txt`.

2. **Processing Connections**:
    - It processes the output to filter for established connections and extracts remote IP addresses, saving them to `target-ip.txt`.

3. **VirusTotal Check**:
    - The C++ program `vt-ip-analyzer` is compiled (if not already compiled) and executed to check each IP address against VirusTotal for any suspicious activity.

## License

MIT_LICENSE
## Contributing

I will not be maintaining this project. I put it together quickly, and I am aware there is room for improvement. If you enhance it, please let me know so I can consider forking your version.
