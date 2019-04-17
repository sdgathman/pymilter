web:
	doxygen
	test -L doc/html/milter_api || ln -sf /usr/share/doc/sendmail-milter-devel doc/html/milter_api
	rsync -ravKk doc/html/ bmsi.com:/var/www/html/pymilter
	cd doc/html; zip -r ../../doc .

VERSION=1.0.4
PKG=pymilter-$(VERSION)
SRCTAR=$(PKG).tar.gz

$(SRCTAR):
	git archive --format=tar.gz --prefix=$(PKG)/ -o $(SRCTAR) $(PKG)

gittar: $(SRCTAR)
