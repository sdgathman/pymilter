web:
	doxygen
	test -L doc/html/milter_api || ln -sf /usr/share/doc/sendmail-devel-* doc/html/milter_api
	rsync -ravKk doc/html/ spidey2.bmsi.com:/Public/pymilter
	cd doc/html; zip -r ../../doc .

VERSION=0.9.6
CVSTAG=pymilter-0_9_6
PKG=pymilter-$(VERSION)
SRCTAR=$(PKG).tar.gz

$(SRCTAR):
	cvs export -r$(CVSTAG) -d $(PKG) pymilter
	tar cvfz $(PKG).tar.gz $(PKG)
	rm -r $(PKG)

cvstar: $(SRCTAR)
