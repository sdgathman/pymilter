web:
	doxygen
	rsync -ravK doc/html/ spidey2.bmsi.com:/Public/pymilter
