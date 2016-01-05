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

DEFAULT_INSTANCEPATH='~/runserval'

import logging
_logger = logging.getLogger(__name__)

try:
    from tkinter import *
    from tkinter.ttk import *
except ImportError:
    from Tkinter import *
    from ttk import *
import select
import socket
import meshy



class DaemonController(object):
    def __init__(self, parent, main_obj):
        self.parent = parent
        self.main = main_obj

        # --- Styles ---
        s = Style()
        s.configure('broken.ServaldFrame.TLabelframe', background='#DA3E3E')
        s.configure('running.ServaldFrame.TLabelframe', background='#4BC04B')
        #Style().configure('TLabel', background='red', foreground='white')
        #~ print(toolbar['style'])
        #~ print(toolbar.winfo_class()) #TLabelframe
        #~ print(Style().layout('TLabelframe'))
        #~ print(Style().element_options('TLabelframe'))
        #~ print(s.lookup('TLabel', 'background'))

        self.indicator = Frame(parent,
                        padding=10,
                        relief=FLAT,
                        )
        self.indicator.pack(fill=BOTH)
        # TODO: Set minimum width for Entry field
        toolbar = Frame(self.indicator, padding=1)
        toolbar.pack(fill=BOTH)

        start_servald_btn = Button(toolbar, text='Start servald',
                                   command=self.cmd_start_servald)
        start_servald_btn.grid(row=0, column=0, padx=(0,2))
        stop_servald_btn = Button(toolbar, text='Stop',
                        command=self.cmd_stop_servald)
        stop_servald_btn.grid(row=0, column=1, padx=2)
        status_btn = Button(toolbar, text='Status',
                            command=self.cmd_servald_status)
        status_btn.grid(row=0, column=2, padx=2)

        cmd_frame = Frame(toolbar)
        cmd_frame.grid(row=0, column=3, sticky=W)
        toolbar.columnconfigure(3, weight=1)

        label = Label(cmd_frame, text='command:')
        label.grid(row=0, column=0, sticky=E)

        self.servalcmd = StringVar()
        # TODO:Dynamically modify text size on window resize
        entry = Entry(cmd_frame, textvariable=self.servalcmd, width=40)
        entry.grid(row=0, column=1, sticky=W)
        btn = Button(cmd_frame, text='Run', default=ACTIVE, command=self.cmd_run_servalcmd)
        btn.grid(row=0, column=2)

        #entry.bind('<Return>', self.cmd_run_servalcmd)
        entry.bind('<Return>', lambda e: btn.invoke())
        entry.focus()

        self.indicator['style'] = 'broken.ServaldFrame.TLabelframe'
        self.monitor_socket = None
        try:
            self.servald = meshy.Servald(
                                    instancepath=DEFAULT_INSTANCEPATH)
            #self.servald = meshy.Servald()
            parent['text'] = 'Local servald : ' + self.servald.instancepath
            res, out = self.servald.exec_cmd(['status'])
            if res == 0:
                self.indicator['style'] = 'running.ServaldFrame.TLabelframe'
                self._init_monitor_socket(self.servald)
        except meshy.ServalError:
            self.main.output('Unable to initialise serval. Please check the '
                'serval logs for details')

    def cmd_run_servalcmd(self, *ign):
        cmd = self.servalcmd.get().split()
        res, out = self.servald.exec_cmd(cmd)
        #TODO:Get unicode output from meshy
        out = out.decode('utf8')
        self.main.output('Exit code:{}\n{}'.format(res, out))

    def cmd_servald_status(self):
        res, out = self.servald.exec_cmd(['status'])
        #TODO:Get unicode output from meshy
        out = out.decode('utf8')
        self.main.output('Exit code:{}\n{}'.format(res, out))

    def cmd_stop_servald(self, *ignore):
        res, out = self.servald.stop_running_daemon()
        if self.monitor_socket:
            self.monitor_socket.close()
        self.monitor_socket = None
        if res == 0:
            self.indicator['style'] = 'ServaldFrame.TLabelframe'
        else:
            self.indicator['style'] = 'broken.ServaldFrame.TLabelframe'
            self.main.output('Exit code:{}\n{}'.format(res, out))

    def cmd_start_servald(self, *ignore):
        try:
            self.servald.start()
            self.indicator['style'] = 'running.ServaldFrame.TLabelframe'
            self._init_monitor_socket(self.servald)
        except meshy.ServalError:
            self.indicator['style'] = 'broken.ServaldFrame.TLabelframe'

    def _init_monitor_socket(self, servald):
        self.monitor_socket = socket.socket(
                                    socket.AF_UNIX, socket.SOCK_STREAM)
        self.monitor_socket.connect('\x00' +
                                servald.instancepath[1:] + '/monitor.socket')
        # Schedule a poll
        self.parent.after(100, self.poll_monitor_socket)

    def poll_monitor_socket(self):
        '''Scheduled function. Checks if the monitor_socket is still
        connected and updates the visual status of the daemon if it is not.
        '''
        if self.monitor_socket is None:
            return
        r,w,x = select.select([self.monitor_socket], [],
                    [self.monitor_socket], 0)  # 0 to return immediately
        resched = True
        if x:  # Exception
            logd('Exception on monitor socket')
            self.monitor_socket.close()
            resched = False
        if r:  # readable
            data = self.monitor_socket.recv(512)
            if data:
                # ignore incoming data
                pass
            else:  # End of File. Remote closed
                self.monitor_socket.close()
                resched = False
        if resched:
            # Re-schedule ourselves
            self.parent.after(100, self.poll_monitor_socket)
        else:
            self.indicator['style'] = 'broken.ServaldFrame.TLabelframe'



class MainWindow(object):

    def output(self, textdata):
        text_replace(self.output_w, textdata)

    def cmd_ZZdujour(self, *args):
        rhizome = self.daemon_controller.servald.get_rhizome()
        #TODO:Get unicode output from meshy
        self.output(repr(rhizome.bundles).decode('utf8'))

    def __init__(self, root):
        # --- Tk init ---
        self.root = root
        self.root.title('MeshTool')
        #self.root.geometry('800x600')

        # Catch the close button
        #self.root.protocol("WM_DELETE_WINDOW", self.cmd_quit)
        # Catch the "quit" event.
        #self.root.createcommand('exit', self.cmd_quit)

        self.root.option_add('*tearOff', False)
        #root.bind('<Return>', self.cmd_ZZdujour)

        # --- Menu ---

        #~ menu = Menu(root)
        #~ root.config(menu=menu)
        #~ def donothing(self): pass  # TODO:remove
        #~ filemenu = Menu(menu)
        #~ filemenu.add_command(label='New...', command=donothing)
        #~ filemenu.add_command(label='Open...', command=donothing)
        #~ filemenu.add_separator()
        #~ filemenu.add_command(label='Quit', command=self.cmd_quit)

        #~ editmenu = Menu(menu)
        #~ editmenu.add_command(label='Copy', command=donothing)

        #~ menu.add_cascade(label='File', menu=filemenu, accelerator='Alt-f')
        #~ menu.add_cascade(label='Edit', menu=editmenu)

        # --- Servald ---

        control_frame = LabelFrame(root, text='Local servald')
        control_frame.grid(row=10, sticky='we', padx=5)#, pady=5)

        # --- Main Content ---

        #Style().configure('TFrame', background='black', foreground='green')
        mainframe = Frame(root)
        mainframe.grid(row=20)
        btn = Button(mainframe, text='List Bundles', command=self.cmd_ZZdujour)
        btn.grid(row=0, column=5)
        btn = Button(mainframe, text='Quit', command=self.cmd_quit)
        btn.grid(row=0, column=6)

        self.output_w = Text(mainframe, width=120, height=20)
        self.output_w.insert('1.0', 'Output will appear here.')
        self.output_w.grid(row=1, column=0, columnspan=7)

        # --- Statusbar ---

        self.status = StringVar()
        status = Label(root, textvariable=self.status, text='Processing...',
                       relief=SUNKEN, anchor=W)
        status.grid(row=30, sticky='wse')

        grip = Sizegrip(status)
        grip.pack(side='right')

        root.columnconfigure(0, weight=1)
        root.rowconfigure(20, weight=1)

        # --- Sub-windows ---
        self.daemon_controller = DaemonController(control_frame, self)

    def cmd_quit(self, *ign):
        logd('cmd_quit called')
        self.root.quit()




# Functions ----------------------------------------------------------
#
logd = _logger.debug


def text_replace(widget, text):
    widget.delete('1.0', 'end')
    widget.insert('1.0', text)


def main(argv):
    logging.basicConfig(
                    format='%(asctime)s:%(name)s:%(levelname)s:%(message)s',
                    datefmt = '%H:%M:%S',
                    level=logging.DEBUG)
    root = Tk()
    obj = MainWindow(root)
    root.mainloop()


if __name__ == '__main__':
    import sys
    main(sys.argv)
