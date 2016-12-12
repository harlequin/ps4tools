ps4tools
========

My collection of tools for PS4 file handling.

Credits
-------
flat_z (original Python scripts for PUP and PKG unpacking)

CHANGELOG
--------

* First Release

	- pupunpack: splits PS4UPDATE.PUP and exposes inner PUP files (encrypted).
	- unpkg: unpacks retail/debug PKG files while collecting data and dumping internal files (mostly a C port of flat_z's Python script, at the moment).
