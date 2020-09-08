
                       Portable UnRAR version


   1. General

   This package includes freeware Unrar C++ source and makefile for
   several Unix compilers.

   Unrar source is subset of RAR and generated from RAR source automatically,
   by a small program removing blocks like '#ifndef UNRAR ... #endif'.
   Such method is not perfect and you may find some RAR related stuff
   unnecessary in Unrar, especially in header files.

   If you wish to port Unrar to a new platform, you may need to edit
   '#define LITTLE_ENDIAN' in os.hpp and data type definitions
   in rartypes.hpp.

   if computer architecture does not allow not aligned data access,
   you need to undefine ALLOW_NOT_ALIGNED_INT and define
   STRICT_ALIGNMENT_REQUIRED in os.h.

   UnRAR.vcproj and UnRARDll.vcproj are projects for Microsoft Visual C++.
   UnRARDll.vcproj lets to build unrar.dll library.


   2. Unrar binaries

   If you compiled Unrar for OS, which is not present in "Downloads"
   and "RAR extras" on www.rarlab.com, we will appreciate if you send
   us the compiled executable to place it to our site.


   3. Acknowledgements

   This source includes parts of code written by other authors.
   Please see acknow.txt file for details.


   4. Legal stuff

   Unrar source may be used in any software to handle RAR archives
   without limitations free of charge, but cannot be used to re-create
   the RAR compression algorithm, which is proprietary. Distribution
   of modified Unrar source in separate form or as a part of other
   software is permitted, provided that it is clearly stated in
   the documentation and source comments that the code may not be used
   to develop a RAR (WinRAR) compatible archiver.

   More detailed license text is available in license.txt.
