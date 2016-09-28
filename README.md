
Meshy: A Desktop interface for a Serval mesh
=============================================

Version: 0.2.0
21 January 2016

Meshy is a tool to use, monitor and manipulate your local node on a
[Serval mesh network][]. You can see peers you're connected to, send and
receive MeshMS messages, start and stop the serval daemon and easily run
serval commands.

The software is written using the Python programming language and uses the
Tk graphical toolkit and so should run on any system which has Python 2.7
or Python 3.4.

All advice and assistance to improve the software will be gratefully received,
as will code reviews, bug reports, patches and any other contributions.

[Serval mesh network]: http://www.servalproject.org/


Features
---------
+ Live Network Peers list
+ Live servald status indication (green=running, red=failed)
+ Easy running of servald cli commands
+ MeshMS send & receive
+ MeshMS templates for Mesh Extender OTA
+ No dependencies: Python & Tkinter


Screenshot
-----------
![screenshot-v0.2](https://cloud.githubusercontent.com/assets/230925/12490972/4b2af2fc-c070-11e5-8180-f4ff99e2e4bc.png)


Install/Run
------------

1. Clone the git repository.

2. Ensure `servald` is in your PATH, or create a link to it in the
   current directory.

3. Run `./meshygui`

For the serval instance path, it will use the following :
    - The first command-line argument
    - The environment variable `SERVALINSTANCE_PATH`
    - `~/meshy/serval`


Contact
--------

Code : <https://github.com/skyguy/meshygui>

I'm subscribed to the <serval-project-developers@googlegroups.com>
mailing list, so I should see any messages posted there, or email me at
<meshy@kevinsteen.net>


License
--------

Copyright 2015-2016 Kevin Steen

Unless otherwise indicated, all source code is Free Software. You can
redistribute it and/or modify it under the terms of the GNU Affero
General Public License as published by the Free Software Foundation,
either version 3 of the License, or (at your option) any later version.
A copy of the license can be found in the file `COPYING`.

---

This file is licensed under the Creative Commons Attribution-ShareAlike
4.0 International License. To view a copy of this license, visit
<http://creativecommons.org/licenses/by-sa/4.0/>
