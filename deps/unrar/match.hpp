#ifndef _RAR_MATCH_
#define _RAR_MATCH_

enum {
   MATCH_NAMES,        // Paths are ignored.
                       // Compares names only using wildcards.

   MATCH_SUBPATHONLY,  // Paths must match either exactly or path in wildcard
                       // must be present in the beginning of file path.
                       // For example, "c:\path1\*" or "c:\path1" will match 
                       // "c:\path1\path2\file".
                       // Names are not compared.

   MATCH_EXACT,        // Paths must match exactly.
                       // Names must match exactly.

   MATCH_ALLWILD,      // Paths and names are compared using wildcards.
                       // Unlike MATCH_SUBPATH, paths do not match subdirs
                       // unless a wildcard tells so.

   MATCH_EXACTPATH,    // Paths must match exactly.
                       // Names are compared using wildcards.

   MATCH_SUBPATH,      // Names must be the same, but path in mask is allowed
                       // to be only a part of name path. In other words,
                       // we match all files matching the file mask 
                       // in current folder and subfolders.

   MATCH_WILDSUBPATH   // Works as MATCH_SUBPATH if file mask contains
                       // wildcards and as MATCH_EXACTPATH otherwise.
};

#define MATCH_MODEMASK           0x0000ffff
#define MATCH_FORCECASESENSITIVE 0x80000000

bool CmpName(const wchar *Wildcard,const wchar *Name,int CmpMode);

#endif
