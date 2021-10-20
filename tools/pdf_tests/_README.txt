Test files for pdf kernels

Didn't use hashcat as password as pdf files/a single pdf hash can
have two passwords, based on the u-value and o-value.
https://www.adobe.com/content/dam/acom/en/devnet/pdf/pdfs/pdf_reference_archives/PDFReference.pdf

The user-password (to open the file is): user
The owner-password (to e.g. restrict printing is): owner

We have files with and without the "_userpw-in-hash" prefix,
this is to accommodate tests for 25400, which needs the user-password
to calculate the o-value. The user-password is used when no owner-password is set.

The pdf files have been made with Adobe Acrobat Pro DC version 2015.007.20003