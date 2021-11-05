# Biff the Buffer

```
   ______  ___  ________ ________      _________  ___  ___  _______           ________  ___  ___  ________ ________ _______   ________     
|\   __  \|\  \|\  _____\\  _____\    |\___   ___\\  \|\  \|\  ___ \         |\   __  \|\  \|\  \|\  _____\\  _____\\  ___ \ |\   __  \    
\ \  \|\ /\ \  \ \  \__/\ \  \__/     \|___ \  \_\ \  \\\  \ \   __/|        \ \  \|\ /\ \  \\\  \ \  \__/\ \  \__/\ \   __/|\ \  \|\  \   
 \ \   __  \ \  \ \   __\\ \   __\         \ \  \ \ \   __  \ \  \_|/__       \ \   __  \ \  \\\  \ \   __\\ \   __\\ \  \_|/_\ \   _  _\  
  \ \  \|\  \ \  \ \  \_| \ \  \_|          \ \  \ \ \  \ \  \ \  \_|\ \       \ \  \|\  \ \  \\\  \ \  \_| \ \  \_| \ \  \_|\ \ \  \\  \| 
   \ \_______\ \__\ \__\   \ \__\            \ \__\ \ \__\ \__\ \_______\       \ \_______\ \_______\ \__\   \ \__\   \ \_______\ \__\\ _\ 
    \|_______|\|__|\|__|    \|__|             \|__|  \|__|\|__|\|_______|        \|_______|\|_______|\|__|    \|__|    \|_______|\|__|\|__|
                                                                                                                                           
```

This is a tool used to aid in fuzzing for BoF vulnerabilities and quickly identifying the offset of the EIP.

It was born as I had very little experience with BoF vulnerabilities and I wanted to learn how to exploit them and create a reliable way to move through each step of the identification and development process.

## Usage

```
usage: biff-the-buffer.py [-h] [-a {fuzz,pattern,offset,chars,verify,exploit}] -i IP -p PORT
                          [-s START] [-e END] [-l LENGTH] [-q QUERY] [-x EXCLUDE] [-o OFFSET]
                          [-r EIP] [-c SHELLCODE] [-t TIMEOUT]

Python based fuzzer with lots of options

optional arguments:
  -h, --help            show this help message and exit
  -a {fuzz,pattern,offset,chars,verify,exploit}, --action {fuzz,pattern,offset,chars,verify,exploit}
                        What action you want to perform on the application, either a fuzz, a pattern
                        create, offset determination, or bad characters
  -i IP, --ip IP        IP address of system to fuzz
  -p PORT, --port PORT  Port number of service/application to fuzz
  -s START, --start START
                        (DEFUALT = None) Start of the string you want to send to application
  -e END, --end END     (DEFUALT = None) End of the string you want to send to application
  -l LENGTH, --length LENGTH
                        Length of the pattern you want to send
  -q QUERY, --query QUERY
                        Value found in EIP when debugger crashed from the pattern create
  -x EXCLUDE, --exclude EXCLUDE
                        (FORMAT = "0f83e189") The chars to exclude in bad char test
  -o OFFSET, --offset OFFSET
                        The offset of the EIP
  -r EIP, --eip EIP     (FORMAT = "0f83e189") The new EIP value you want to send in your payload as a
                        string
  -c SHELLCODE, --shellcode SHELLCODE
                        The /path/to/shellcode you want sent in the buffer
  -t TIMEOUT, --timeout TIMEOUT
                        (DEFAULT = 2s) How long the timeout should be for the connection

```

## Examples

Some exploits will require raw bytes to be sent at the beginning or end. To handle those cases, provide the bytes in the string like below:

```
./biff-the-buffer.py -i 192.168.221.44 -p 13327 -s "\x11(setup sound " -e "\x90\x00#" -a fuzz
```

## Known Limitations

The start and end options can have a mixture of bytes and ascii however, if there are any instances of a legtimate byte in the form of '\\x00' then that will be mangled by the script parsing.

## Potenital Improvements

* Ability to send the path of the MSF modules.
* Ability to quickly run the next "step" of determining the overflow
