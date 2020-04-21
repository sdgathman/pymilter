web:
	doxygen
	test -L doc/html/milter_api || ln -sf /usr/share/doc/sendmail-milter-devel doc/html/milter_api
	rsync -ravKk doc/html/ pymilter.org:/var/www/html/milter/pymilter
	cd doc/html; zip -r ../../doc .

VERSION=1.0.5
PKG=pymilter-$(VERSION)
SRCTAR=$(PKG).tar.gz

$(SRCTAR):
	git archive --format=tar.gz --prefix=$(PKG)/ -o $(SRCTAR) $(PKG)

# add extra copy of name like github so annoyingly does...
github:
	git archive --format=tar.gz --prefix=pymilter-$(PKG)/ -o $(SRCTAR) $(PKG)

gittar: $(SRCTAR)
