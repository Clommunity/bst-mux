bst-mux
=======

Multiuser system for SyncThing, using Docker and Go.

# Dev
this version use Gorilla-mux ( http://www.gorillatoolkit.org/pkg/mux ) to Router web request, and restangular ( https://github.com/mgonto/restangular ) 

# Install

* Install Docker:You can follow Docker web site. ( https://docs.docker.com/installation/ )

* Install bst-mux:TODO

- Prepare Docker Execute Dockerfile ?

- Prepare Directories

	mkdir -p /home/syncthing/real

- Create synching user

	adduser --home /home/syncthing --uid 22000 -g users --disable-password syncthing

- Change permisions

	chown -R 22000 /home/syncthing

-  Copy config.xml default

	cp res/config.xml.orig /home/syncthing/config.xml

-  Run bst-mux

	go run main.go

# Setup

  The first user to registed in system has in admins group, this user can create, update, delete users.
