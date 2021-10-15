#!/usr/bin/env python3

import socket, time, sys, argparse, subprocess

def main():

  # Parse the command line arguments
  parser = argparse.ArgumentParser(description='Python based fuzzer with lots of options')
  parser.add_argument('-a', '--action', choices=["fuzz", "pattern"], help="What action you want to perform on the application, either a fuzz or just a pattern create")
  parser.add_argument('-i', '--ip', type=str, help="IP address of system to fuzz", required=True)
  parser.add_argument('-p', '--port', type=int, help="Port number of service/application to fuzz", required=True)
  parser.add_argument('-s', '--start', default="", type=str, help="(DEFUALT = None) Start of the string you want to send to application")
  parser.add_argument('-e', '--end', default="", type=str, help="(DEFUALT = None) End of the string you want to send to application")
  parser.add_argument('-l', '--length', type=int, help="Length of the pattern you want to send")
  parser.add_argument('-t', '--timeout', default=2, type=int, help='(DEFAULT = 2s) How long the timeout should be for the connection')
  args = parser.parse_args()

  # Get relevant args
  action = args.action
  ip = args.ip
  port = args.port
  start = args.start
  end = args.end
  length = args.length
  timeout = args.timeout

  

  # Create string to send to app
  if action == 'fuzz':
    inc = 1
    string = start + "A" * 100 + end

    while True:
      num_bytes = 100 * inc
      string = start + "A" * num_bytes + end
      try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
          s.settimeout(timeout)
          s.connect((ip, port))
          s.recv(1024)
          print("Fuzzing with {} bytes".format(len(string) - len(start)))
          s.send(bytes(string, "latin-1"))
          s.recv(1024)
      except:
        print("Fuzzing crashed at {} bytes".format(len(string) - len(start)))
        sys.exit(0)
      inc += 1
      time.sleep(1)

  elif action == 'pattern':
    if (length is None): raise Exception("Must supply a length if using pattern")
    pattern = create_pattern(length)
    string = start + f"{pattern}" + end
    try:
      with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        s.connect((ip, port))
        s.recv(1024)
        print(f"Sending pattern of size {length}")
        s.send(bytes(string, "latin-1"))
        s.recv(1024)
    except:
      print("Check your debugger for a crash")
      print("Run 'pattern_offset.rb' to determine the EIP offset")

def system_call(command, timeout=0):
  if (timeout == 0):
    return subprocess.check_output(command, stderr=subprocess.STDOUT)
  return subprocess.check_output(command, stderr=subprocess.STDOUT, timeout=timeout)

def create_pattern(length, path_to_pattern_create="/usr/share/metasploit-framework/tools/exploit/pattern_create.rb"):
  return system_call([path_to_pattern_create, "-l", f"{length}"]) 

if __name__ == "__main__":
  main()
