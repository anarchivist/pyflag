RFC reference:
RFC 1341 - base64 Mime encoding and layout of mime headers
RFC 2183 - Content-Disposition for describing email attachments
RFC 2426 - vCard definition (for saving contacts)

LibPST v0.5
===========

It is with GREAT relief that I bring you version 0.5 of the LibPST tools!

Through great difficulties, this tool has survived and expanded to become even
better.

The changes are as follows:
  * RTF support. We can now decompress RTF bodies in emails, and are saved as attachments
  * Better support in reading the indexes. Fixed many bugs with them
  * Improved reliability. "Now we are getting somewhere!"
  * Improved compiling. Hopefully we won't be hitting too many compile errors now.
  * vCard handling. Contacts are now exported as vCard entries.
  * vEvent handling. Support has begun on exporting Calendar entries as events
  * Support for Journal entries has also begun

If you have any problems with this release, don't hesitate to contact me.

These changes come to you, as always, free under the GPL license!! What a wonderful
thing it is. It does mean that you can write your own program off of this library
and distribute it also for free. However, anyone with commercial interests for
developing applications they will be charging for are encouraged to get in touch
with me, as I am sure we can come to some arrangement.

Dave Smith
<dave.s@earthcorp.com>

LibPST v0.4.3
=============

Bug fix release. No extra functionality

Dave Smith
<dave.s@earthcorp.com>

LibPST v0.4.2
=============

The debug system has had an overhaul. The debug messages are no longer
printed to the screen when they are enabled. They are dumped to a
binary file. There is another utility called "readlog" that I have
written to handle these log files. It should make it easier to
selectively view bits of a log file. It also shows the position that
the log message was printed from.

There is a new switch in readpst. It is -d. It enables the user to
specify the log file which the binary log is written to. If the switch
isn't used, the default file of "readpst.log" is used.

The code is now Visual C++ compatible. It has compiled on Visual C++
.net Standard edition, and produces the readpst.exe file. Use the project
file included in this distribution.

There have been minor improvements elsewhere too.


LibPST v0.4.1
=============

Fixed a couple more bugs. Is it me or do bugs just insert themselves
in random, hard to find places!

Cured a few problems with regard to emails with multiple embeded
items. They are not fully re-created using Mime-types, but are
accessible with the -S switch (which saves everything as seperate
items)

Fixed a problem reading the first index. Back sliders are now
detected. (ie when the value following the current one is smaller, not
bigger!)

Added some error messages when we try and read outside of the PST
file, this was causing a few problems before, cause the return value
wasn't always checked, so it was possible to be reading random data,
and trying to make sense of it!

Anyway, if you find any problems, don't hesitate to mail me

Dave Smith
<dave.s@earthcorp.com>

LibPST v0.4
===========

Fixed a nasty bug that occasionally corrupted attachments. Another bug
with regard to reading of indexes (also occasional).

Another output method has been added which is called "Seperate". It is
activated with the -S switch. It operates in the following manor:

  |--Inbox-->000000
  |	     000001
  |	     000002
  |--Sentmail-->0000000
  |		0000001
  |		0000002

All the emails are stored in seperate files counting from 0 upwards,
in a folder named as the PST folder.

When an email has an attachment, it is saved as a seperate file. The
filename for the attachment is made up of 2 parts, the first is the
email number to which it belongs, the second is its filename.

The should now be runnable on big-endian machines, if the define.h
file is first modified. The #define LITTLE_ENDIAN must be commented
out, and the #define BIG_ENDIAN must be uncommented.

More verbose error messages have been added. Apparently people got
confused when the program stopped for no visible reason. This has now
been resolved.

Thanks for the continued support of all people involved.

Dave Smith
<dave.s@earthcorp.com>

Libpst v0.3.4
=============

Several more fixes. An Infinite loop and incorrect interpreting of
item index attributes. Work has started on making the code executable
on big endian CPUs. At present it should work with Linux on these
CPUs, but I would appreciate it if you could provide feedback with
regard to it's performance. I am also working with some other people
at make it operate on Solaris.

A whole load more items are now recognized by the Item records. With
more items in Emails and Folders. I haven't got to the Contacts yet.

Anyway, this is what I would call a minor feature enhancment and
bugfix release.

Dave Smith
<dave.s@earthcorp.com>

LibPST v0.3.3
=============

Fixed several items. Mainly memory leaks. Loads of them! oops..

I have added a new program, mainly of debugging, which when passed
an ID value and a pst file, will extract and decrypt that ID from 
the pst file. I don't see it being a huge attraction, or of much use
to most people, but it is another example of writing an application
to use the libpst interface.

Another fix was in the reading of the item index. This has hopefully
now been corrected. The result of this bug was that not all the emails
in a folder were converted. Hopefully you should have more luck now.

Dave Smith
<dave.s@earthcorp.com>

LibPST v0.3.2
=============

Quick bugfix release. There was a bug in the decryption of the basic
encryption that outlook uses. One byte, 0x6c, was incorrectly decrypted
to 0x6c instead of 0xcd. This release fixes this bug. Sorry...


LibPST v0.3.1
=============

Minor improvements. Fixed bug when linking multiple blocks together,
so now the linking blocks are not "encrypted" when trying to read
them.


LibPST v0.3
===========

A lot of bug fixing has been done for this release. Testing has been
done on the creation of the files by readpst.  Better handling of
large binaries being extracted from the PST file has been implemented.

Quite a few reports have come in about not being able to compile on
Darwin. This could be down to using macros with variable parameter
lists. This has now been changed to use C functions with variable
parameters. I hope this fixes a lot of problems.

Added support for recreating the folder structure into normal
directories. For Instance:

Personal Folders
  |-Inbox
  |   |-Jokes
  |   |-Meetings
  |-Send Items

each folder containing an mbox file with the correct emails for that
folder.

Dave Smith
<dave.s@earthcorp.com>


LibPST v0.3 beta1
=================

Again, a shed load of enhancements. More work has been done on the
mime creation. A bug has been fixed that was letting part of the
attachments that were created disappear. 

A major enhancement is that "compressible encryption" support has been
added. This was an incredibly simple method to use. It is basically a
ceasar cipher. It has been noted by several users already that the PST
password that Outlook uses, serves *no purpose*. It is not used to
encrypt the PST, it is mearly stored there. This means that the
readpst application is able to convert PST files without knowing the
password. Microsoft have some explaning to do!

Output files are now not overwritten if they already exist. This means
that if you have two folders in your PST file named "fred", the first
one encountered will be named "fred" and the second one will be named
"fred00000001". As you can see, there is enough room there for many
duplicate names!

Output filenames are now restricted. Any "/" or "\" characters in the
name are replaced with "_". If you find that there are any other
characters that need to be changed, could you please make me aware!

Thanks to Berry Wizard for help with supporting the encryption.

Thanks to Auke Kok, Carolus Walraven and Yogesh Kumar Guatam for providing debugging
information and testing.

Dave Smith
<dave.s@earthcorp.com>


LibPST v0.2 beta1
=================

Hello once more...

Attachments are now re-created in mime format. The method is very
crude and could be prone to over generalisation. Please test this
version, and if attachments are not recreated correctly, please send
me the email (complete message source) of the original and
converted. Cheers.

I hope this will work for everyone who uses this program, but reality
can be very different!

Let us see how it goes...

Dave Smith
<dave.s@earthcorp.com>

LibPST v0.2 alpha1
===========

Hello!

Some improvements. The internal code has been changed so that
attachments are now processed and loaded into the structures. The
readpst program is not finished yet. It needs to convert these binary
structs into mime data. At present it just saves them to the current
directory, overwriting any previous files with the attachment name.

Improvements over previous version: 
* KMail output is supported - if the "-k" flag is specified, all the
  directory hierarchy is created using the KMail standard
* Lots of bugs and memory leaks fixed


Usage:

ReadPST v0.2alpha1 implementing LibPST v0.2alpha1
Usage: ./readpst [OPTIONS] {PST FILENAME}
OPTIONS:
        -h      - Help. This screen
        -k      - KMail. Output in kmail format
        -o      - Output Dir. Directory to write files to. CWD is changed *after* opening pst file
        -V      - Version. Display program version

If you want to view lots of debug output, modify a line in "define.h"
from "//#define DEBUG_ALL" to "#define DEBUG_ALL". It would then be
advisable to pipe all output to a log file:

./readpst -o out pst_file &> logfile

Dave Smith

LibPST v0.1
===========

Hi Folks!

This has been a long, hard slog, but I now feel that I have got
somewhere useful. The included program "main" is able to read an
Outlook PST file and dump the emails into mbox files, separating each
folder into a different mbox file. All the mbox files are stored in
the current directory and no attempt is yet made to organise these
files into a directory hierarchy. This would not be too difficult to
achieve though.

Email attachments are not yet handled, neither are Contacts.

There is no pretty interface yet, but you can convert a PST file in
the following manner

./main {path to PST file}

This is very much a work in progress, but I thought I should release
this code so that people can lose their conception that outlook files
will never be converted to Linux.

I am intending that the code I am writing will be developed into
greater applications to provide USEFUL tools for accessing and
converting PST files into a variety of formats.

One point I feel I should make is that Outlook, by default, creates
"Compressible Encryption" PST files. I have not, as yet, attempted to
write any decryption routines, so you will not be able to convert
these files. However, if you create a new PST file and choose not to
make an encrypted one, you can copy all your emails into this new one
and then convert the unencrypted one.

I hope you enjoy,

Dave Smith
