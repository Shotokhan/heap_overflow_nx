#!/bin/sh
if [ ! -f "./heappy" ]; then
	make all
fi
socat -T10 TCP4-LISTEN:5000,fork,reuseaddr,bind=0.0.0.0 EXEC:'./heappy',pty,stderr

