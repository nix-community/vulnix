all: vulnix.1 vulnix-whitelist.5

clean:
	rm -f vulnix.1 vulnix.1.html vulnix-whitelist.5 vulnix-whitelist.5.html

%: %.md
	ronn -w \
	    --organization "Version `cat ../VERSION`" \
	    --manual 'User Commands' \
	    $<

.PHONY: all clean
