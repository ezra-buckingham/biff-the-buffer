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
usage: biff.py [-h] [-a {fuzz,pattern,offset,chars,verify,exploit}] -i IP -T
               TEMPLATE -p PORT [-l LENGTH] [-q QUERY] [-x EXCLUDE]
               [-o OFFSET] [-e EIP] [-s SHELLCODE] [-t TIMEOUT]

Python based fuzzer with lots of options

optional arguments:
  -h, --help            show this help message and exit
  -a {fuzz,pattern,offset,chars,verify,exploit}, --action {fuzz,pattern,offset,chars,verify,exploit}
                        What action you want to perform on the application,
                        either a fuzz, a pattern create, offset determination,
                        bad character identification, verification of EIP, and
                        exploitation
  -i IP, --ip IP        IP address of system to fuzz
  -T TEMPLATE, --template TEMPLATE
                        A jinja template that will be used in building the
                        payload for the exploit
  -p PORT, --port PORT  Port number of service/application to fuzz
  -l LENGTH, --length LENGTH
                        Length of the pattern you want to send
  -q QUERY, --query QUERY
                        Value found in EIP when debugger crashed from the
                        pattern create
  -x EXCLUDE, --exclude EXCLUDE
                        (FORMAT = "0f83e189") The chars to exclude in bad char
                        test
  -o OFFSET, --offset OFFSET
                        The offset of the EIP
  -e EIP, --eip EIP     (FORMAT = "0f83e189") The new EIP value you want to
                        send in your payload as a string
  -s SHELLCODE, --shellcode SHELLCODE
                        The /path/to/shellcode you want sent in the buffer
  -t TIMEOUT, --timeout TIMEOUT
                        (DEFAULT = 2s) How long the timeout should be for the
                        connection

```

## Examples

Some exploits will require more complex payloads. For example, some buffer overflows exist in web applications and need to be passed into the application as an HTTP request. Since Biff only uses a socket to connect, we need to manually build out the request. To alleviate this issue, you need to pass Biff a jinja template in where you use the `{{ payload }}` variable (curly braces are jinja2 syntax, please be familiar with it before trying to use Biff). An example of the HTTP request jinja template would look like:

```
Lorem Ipsum
```

And then to execute the overflow would look something like this:

```
./biff-the-buffer.py -i 192.168.221.44 -p 13327 -s "\x11(setup sound " -e "\x90\x00#" -a fuzz
```

## Potenital Improvements

* Ability to send the path of the MSF modules.
* Ability to quickly run the next "step" of determining the overflow
