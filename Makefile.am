
INSTALL_FOLDER          ?= $(bindir)
LIBRARY_FOLDER          ?= $(libdir)
SHARED_FOLDER           ?= $(datadir)/@PACKAGE@/
DOCUMENT_FOLDER         ?= $(docdir)

SUBDIRS= src

examplesdir = $(DOCUMENT_FOLDER)/examples

examples_DATA = \
	$(top_srcdir)/example.dict \
	$(top_srcdir)/example0.hash \
	$(top_srcdir)/example400.hash \
	$(top_srcdir)/example500.hash \
	$(top_srcdir)/example0.sh \
	$(top_srcdir)/example400.sh \
	$(top_srcdir)/example500.sh \
	$(NULL)

DOC_FILES= \
    $(top_srcdir)/charsets/* \
    $(top_srcdir)/docs/* \
    $(top_srcdir)/extra/* \
    $(top_srcdir)/include/* \
    $(top_srcdir)/masks/* \
    $(top_srcdir)/OpenCL/* \
    $(top_srcdir)/rules/* \
    $(top_srcdir)/tools/* \
    ChangeLo* \
    $(NULL)

EXTRA_DIST=autogen.sh autoclean.sh AUTHORS README.md \
	$(DOC_FILES) $(examples_DATA) \
	$(NULL)

uninstall-local:
	chmod -R u+w '$(DESTDIR)$(DOCUMENT_FOLDER)'
	rm -rf '$(DESTDIR)$(DOCUMENT_FOLDER)'
#.PHONY: install-examples-source

FIND=find

install-data-local: install-examples-source $(top_srcdir)/OpenCL/*
	mkdir -p "$(DESTDIR)$(SHARED_FOLDER)/OpenCL/"
	$(INSTALL_DATA) $(top_srcdir)/OpenCL/*       "$(DESTDIR)$(SHARED_FOLDER)/OpenCL/"
	$(INSTALL_DATA) $(top_srcdir)/hashcat.hcstat "$(DESTDIR)$(SHARED_FOLDER)/"
	$(INSTALL_DATA) $(top_srcdir)/hashcat.hctune "$(DESTDIR)$(SHARED_FOLDER)/"

install-examples-source:
	cd $(top_srcdir)/ ; \
	for d in \
		docs \
		charsets \
		masks \
		rules \
		extra; do \
		$(MKDIR_P) "$(DESTDIR)$(DOCUMENT_FOLDER)/$$d"; \
		$(FIND) "$$d" -type d -exec $(INSTALL) -m 755 -d    $(DESTDIR)$(DOCUMENT_FOLDER)/{} \; ; \
		$(FIND) "$$d" -type f -exec $(INSTALL) -m 644 {}    $(DESTDIR)$(DOCUMENT_FOLDER)/{} \; ; \
	done && \
	chmod 755 '$(DESTDIR)$(DOCUMENT_FOLDER)/extra/tab_completion/hashcat.sh' && \
	echo Done \
	$(NULL)


ChangeLog: .git
	if test -d $(srcdir)/.git; then                         \
	  if test -f $(srcdir)/.last-cl-gen; then               \
        git log --no-merges --date-order --date=short       \
          $$(cat $(srcdir)/.last-cl-gen)..                  \
          | sed -e  '/^commit.*$$/d'                        \
          | awk '/^Author/ {sub(/\\$$/,""); getline t; print $$0 t; next}; 1' \
          | sed -e 's/^Author: //g'                         \
          | sed -e 's/>Date:   \([0-9]*-[0-9]*-[0-9]*\)/>\t\1/g' \
          | sed -e 's/^\(.*\) \(\)\t\(.*\)/\3    \1    \2/g' \
          > ChangeLog.tmp;                                  \
      else                                                  \
        git log --no-merges --date-order --date=short       \
          | sed -e  '/^commit.*$$/d'                        \
          | awk '/^Author/ {sub(/\\$$/,""); getline t; print $$0 t; next}; 1' \
          | sed -e 's/^Author: //g'                         \
          | sed -e 's/>Date:   \([0-9]*-[0-9]*-[0-9]*\)/>\t\1/g' \
          | sed -e 's/^\(.*\) \(\)\t\(.*\)/\3    \1    \2/g' \
          > ChangeLog.tmp;                                  \
      fi;                                                   \
	  touch ChangeLog                                       \
	    && git rev-list -n 1 HEAD >.last-cl-gen.tmp         \
        && (echo; cat $(srcdir)/ChangeLog) >>ChangeLog.tmp  \
        && mv -f ChangeLog.tmp $(srcdir)/ChangeLog          \
        && mv -f .last-cl-gen.tmp $(srcdir)/.last-cl-gen    \
        && rm -f ChangeLog.tmp;                             \
    fi
	if test -d $(srcdir)/.hg; then                          \
        hg log --template changelog > ChangeLog;            \
        touch $(srcdir)/.last-cl-gen;                       \
    fi

