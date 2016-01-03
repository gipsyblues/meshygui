#!/usr/bin/env python
# -*- Encoding: utf-8 -*-
#
#  A GUI tool for working with the Serval mesh software
#
#  Copyright 2015 Kevin Steen <ks@kevinsteen.net>
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU Affero General Public License as
#  published by the Free Software Foundation, either version 3 of the
#  License, or (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU Affero General Public License for more details.
#
#  You should have received a copy of the GNU Affero General Public License
#  along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
'''Mesh Toolkit

A GUI tool for working with the Serval Mesh software
'''
from __future__ import print_function, unicode_literals

__version_info__ = (0, 1, 0)

import logging
_logger = logging.getLogger(__name__)

try:
    from tkinter import *
    from tkinter.font import *
    from tkinter.ttk import *
    from tkinter import messagebox as tkMessageBox
except ImportError:
    from Tkinter import *
    from tkFont import *
    from ttk import *
    import tkMessageBox
import meshy
import subprocess

def text_replace(widget, text):
    widget.delete('1.0', 'end')
    widget.insert('1.0', text)

    
class MainWindow(object):

    def cmd_ZZdujour(self, *args):
        rhizome = self.servald.get_rhizome()
        text_replace(self.output, repr(rhizome.bundles).decode('utf8'))
        #subprocess.call()
        
    def __init__(self, root):
        self.servald = meshy.Servald(instancepath='runserval')

        # --- Tk init ---
        self.root = root
        self.root.title('MeshTool')
        self.root.geometry('800x600')

        # Catch the close button
        self.root.protocol("WM_DELETE_WINDOW", self.cmd_quit)
        # Catch the "quit" event.
        self.root.createcommand('exit', self.cmd_quit)

        self.root.option_add('*tearOff', FALSE)
        #~ menu = Menu(root)
        #~ root.config(menu=menu)

        #~ filemenu = Menu(menu)
        #~ filemenu.add_command(label='New...', command=donothing)
        #~ filemenu.add_command(label='Open...', command=donothing)
        #~ filemenu.add_separator()
        #~ filemenu.add_command(label='Quit', command=self.cmd_quit)

        #~ editmenu = Menu(menu)
        #~ editmenu.add_command(label='Copy', command=donothing)

        #~ menu.add_cascade(label='File', menu=filemenu)
        #~ menu.add_cascade(label='Edit', menu=editmenu)

        # --- Toolbar ---
        toolbar = LabelFrame(root, text='Local servald')
        toolbar.pack(side='bottom', fill='x', padx=5, pady=5)

        start_servald_btn = Button(toolbar, text='Start servald', command=self.cmd_start_servald)
        start_servald_btn.pack(side='left', padx=5)
        stop_servald_btn = Button(toolbar, text='Stop', command=self.cmd_stop_servald)
        stop_servald_btn.pack(side='left', padx=5)
        self.servalcmd = StringVar()
        entry = Entry(toolbar, textvariable=self.servalcmd, width=40)
        entry.pack(side='left', fill='x')
        btn = Button(toolbar, text='Run', command=self.cmd_run_servalcmd)
        btn.pack(side='left')
        btn = Button(toolbar, text='Quit', command=self.cmd_quit)
        btn.pack(side='right', padx=5)
        entry.bind('<Return>', self.cmd_run_servalcmd)


        for child in toolbar.winfo_children():
            child.pack_configure(padx=5, pady=5)
        entry.focus()

        # --- Statusbar ---

        self.status = StringVar()
        status = Label(root, textvariable=self.status, text='Processing...',
                       relief=SUNKEN, anchor=W)
        status.pack(side='bottom', fill=X)

        # --- Main Content ---
        #Style().configure('TFrame', background='black', foreground='green')
        mainframe = Frame(root)
        mainframe.pack(fill=Y)
        btn = Button(mainframe, text='Cmd du jour', command=self.cmd_ZZdujour)
        btn.pack(side='top', padx=5)

        self.output = Text(mainframe)#, width=120, height=20)
        self.output.insert('1.0', 'Output will appear here.')
        self.output.pack(fill=BOTH)
        
        #Style().configure('TLabel', background='red', foreground='white')

        #root.bind('<Return>', self.cmd_ZZdujour)


    def cmd_quit(self, *ign):
        logd('cmd_quit called')
        self.root.quit()

    def cmd_start_servald(self):
        self.servald.start()
        
    def cmd_stop_servald(self):
        self.servald.stop_running_daemon()

    def cmd_run_servalcmd(self, *ign):
        cmd = self.servalcmd.get().split()
        res, out = self.servald.exec_cmd_withoutput(cmd)
        out = out.decode('utf8')
        text_replace(self.output, 'Exit code:{}\n{}'.format(res, out))


# Functions ----------------------------------------------------------
#
def logd(*args):
    '''log args at level `Debug`'''
    _logger.debug(args)


def main():
    logging.basicConfig(
                    format='%(asctime)s:%(name)s:%(levelname)s:%(message)s',
                    datefmt = '%H:%M:%S',
                    level=logging.DEBUG)
    root = Tk()
    obj = MainWindow(root)
    root.mainloop()


if __name__ == '__main__':
    main()
