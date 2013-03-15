web:
	doxygen
	cd doc/html; zip -r ../../doc .
	rsync -ravK doc/html/ spidey2.bmsi.com:/Public/pymilter

VERSION=0.9.8
CVSTAG=pymilter-0_9_8
PKG=pymilter-$(VERSION)
SRCTAR=$(PKG).tar.gz

$(SRCTAR):
	cvs export -r$(CVSTAG) -d $(PKG) pymilter
	tar cvfz $(PKG).tar.gz $(PKG)
	rm -r $(PKG)

cvstar: $(SRCTAR)
