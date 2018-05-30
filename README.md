ps4tools
========

My collection of tools for PS4 file handling.

Credits
-------

flat_z (original Python scripts for PUP and PKG unpacking)

zecoxao (updates and bug fixes)

CrazyVoid (for genidx sources)

zecoxao (for undat sources)

CHANGELOG
--------

* First Release

	- pupunpack: splits PS4UPDATE.PUP and exposes inner PUP files (encrypted).
	- unpkg: unpacks retail/debug PKG files while collecting data and dumping internal files (mostly a C port of flat_z's Python script, at the moment).
	- unpfs: unpacks pfs images
	- trophy: unpack trophy files (incl. bruteforce for npcommid)
	- genidx: generate PS4 IDX File
	- undat: index.dat decrypter for ps4
	- fpkg_rename: Renames fpkg into following format $TITLE - ($TITLE_ID) ($VERSION).pkg
