# Biff the Buffer

This is a tool used to aid in fuzzing for BoF vulnerabilities and quickly identifying the offset of the EIP.

## Usage

```
usage: biff-the-buffer.py [-h] [-a {fuzz,pattern,chars}] -i IP -p PORT [-s START] [-e END] [-l LENGTH] [-t TIMEOUT]

Python based fuzzer with lots of options

optional arguments:
  -h, --help            show this help message and exit
  -a {fuzz,pattern,chars}, --action {fuzz,pattern,chars}
                        What action you want to perform on the application, either a fuzz, a pattern create, or bad
                        characters
  -i IP, --ip IP        IP address of system to fuzz
  -p PORT, --port PORT  Port number of service/application to fuzz
  -s START, --start START
                        (DEFUALT = None) Start of the string you want to send to application
  -e END, --end END     (DEFUALT = None) End of the string you want to send to application
  -l LENGTH, --length LENGTH
                        Length of the pattern you want to send
  -t TIMEOUT, --timeout TIMEOUT
                        (DEFAULT = 2s) How long the timeout should be for the connection

```
