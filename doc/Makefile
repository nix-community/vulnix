all: vulnix.1 vulnix-whitelist.5

%: %.md
	ronn -w \
	    --organization "Version `cat ../VERSION`" \
	    --manual 'User Commands' \
	    $< > $@

.PHONY: all
