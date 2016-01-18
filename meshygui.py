#!/usr/bin/env python
# -*- Encoding: utf-8 -*-
#
#  Meshy: The graphical interface for the Serval mesh
#
#  Copyright 2015-2016 Kevin Steen <ks@kevinsteen.net>
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
'''Meshy

The graphical interface for the Serval mesh
'''
from __future__ import print_function, unicode_literals

__version_info__ = (0, 1, 0)

DEFAULT_INSTANCEPATH='~/meshy/serval'

import logging
_logger = logging.getLogger(__name__)

try:
    import tkinter as tk
    from tkinter import messagebox
    import tkinter.ttk as ttk
except ImportError:
    import Tkinter as tk
    import tkMessageBox as messagebox
    import ttk
import select
import meshy



class MainWindow(object):

    def output(self, text):
        self.output_tab_obj.replace_text(text)

    def cmd_ZZdujour(self, *args):
        servald = self.daemon_controller.servald
        #TODO:Get unicode output from meshy
        self.output(servald.keyring)

    def __init__(self, root):
        # --- Tk init ---
        self.root = root
        self.root.title('MeshTool')
        #self.root.geometry('800x600')

        # Catch the close button
        self.root.protocol("WM_DELETE_WINDOW", self.cmd_quit)
        # Catch the "quit" event.
        #self.root.createcommand('exit', self.cmd_quit)

        self.root.option_add('*tearOff', False)
        root.bind('<Alt_L><q>', self.cmd_quit)
        #root.bind('<Return>', self.cmd_ZZdujour)

        # --- Menu ---

        #~ menu = tk.Menu(root)
        #~ root.config(menu=menu)
        #~ def donothing(self): pass  # TODO:remove
        #~ filemenu = tk.Menu(menu)
        #~ #logd(filemenu.configure())
        #~ filemenu.add_command(label='Open...', underline=0, command=donothing)
        #~ filemenu.add_separator()
        #~ filemenu.add_command(label='Quit', underline=0, command=self.cmd_quit)
#~ 
        #~ editmenu = tk.Menu(menu)
        #~ editmenu.add_command(label='Copy', underline=0, command=donothing)
#~ 
        #~ menu.add_cascade(label='File', menu=filemenu, underline=0)
        #~ menu.add_cascade(label='Edit', menu=editmenu, underline=0)

        # --- Current Identity bar ---

        idframe = ttk.Frame(root)
        idframe.grid(row=10, column=0, columnspan=2, sticky='new')
        btn = ttk.Button(idframe, text='Quit', command=self.cmd_quit, underline=0)
        btn.grid(row=0, column=0)
        lbl = ttk.Label(idframe, text='Current Identity:', anchor='e')
        lbl.grid(row=0, column=1)
        self.current_sid = ttk.Label(idframe, anchor='w')
        lbl.grid(row=0, column=2)
        
        
        # --- Main Content ---

        #Style().configure('TFrame', background='black', foreground='green')
        mainframe = ttk.Frame(root)#, borderwidth=10, relief='ridge')
        mainframe.grid(row=20, column=0, columnspan=2, sticky='nsew')
        self._init_mainframe(mainframe)
        
        # --- Daemon control ---

        control_frame = ttk.LabelFrame(root, text=' Local servald ')
        control_frame.grid(row=30, column=0, sticky=tk.EW, padx=5,
                           columnspan=2)

        # --- Statusbar ---

        self.status = tk.StringVar()
        #self.status.set('Processing...')
        status = ttk.Label(root, textvariable=self.status, 
                       relief=tk.SUNKEN, anchor=tk.W)
        status.grid(row=40, column=0, sticky='wse')

        grip = ttk.Sizegrip(root)
        grip.grid(row=40, column=1, sticky=tk.SE)

        root.columnconfigure(0, weight=1)
        root.rowconfigure(20, weight=1)

        # --- Sub-windows ---
        self.daemon_controller = DaemonController(control_frame, self)

    def _init_mainframe(self, parent):
        pw = ttk.PanedWindow(parent, orient=tk.HORIZONTAL)
        pw.pack(fill=tk.BOTH)
        pw.grid(row=0, column=0, sticky=tk.NSEW)
        
        treepane = ttk.Frame(pw)#, borderwidth=10, relief='ridge')
        pw.add(treepane, weight=1)
        self.tree_obj = TreeManager(treepane, self)
        
        mainpane = ttk.Frame(pw)#, borderwidth=10, relief='ridge')
        pw.add(mainpane, weight=4)

        self.tabs_w = ttk.Notebook(mainpane)
        self.tabs_w.pack()
        
        self.peer_tab_obj = PeerTab(self.tabs_w, self)
        self.output_tab_obj = OutputTab(self.tabs_w, self)
        self.output_tab_obj.show()

    def cmd_quit(self, *ign):
        logd('cmd_quit called')
        self.root.quit()



class DaemonController(object):
    def __init__(self, parent, main_obj):
        self.parent = parent
        self.main_obj = main_obj

        # --- Styles ---
        s = ttk.Style()
        s.configure('broken.ServaldFrame.TLabelframe', background='#DA3E3E')
        s.configure('running.ServaldFrame.TLabelframe', background='#4BC04B')
        #ttk.Style().configure('TLabel', background='red', foreground='white')
        #~ print(toolbar['style'])
        #~ print(toolbar.winfo_class()) #TLabelframe
        #~ print(ttk.Style().layout('TLabelframe'))
        #~ print(ttk.Style().element_options('TLabelframe'))
        #~ print(s.lookup('TLabel', 'background'))

        self.indicator = ttk.Frame(parent,
                        padding=10,
                        relief=tk.FLAT,
                        )
        self.indicator.pack(fill=tk.BOTH)
        # TODO: Set minimum width for Entry field
        toolbar = ttk.Frame(self.indicator, padding=1)
        toolbar.grid(sticky='wns')

        start_servald_btn = ttk.Button(toolbar, text='Start servald',
                                   command=self.cmd_start_servald)
        start_servald_btn.grid(row=0, column=0, padx=(0,2))
        stop_servald_btn = ttk.Button(toolbar, text='Stop',
                        command=self.cmd_stop_servald)
        stop_servald_btn.grid(row=0, column=1, padx=2)
        status_btn = ttk.Button(toolbar, text='Status',
                            command=self.cmd_servald_status)
        status_btn.grid(row=0, column=2, padx=2)

        cmd_frame = ttk.Frame(toolbar)
        cmd_frame.grid(row=0, column=3, sticky=tk.W)

        label = ttk.Label(cmd_frame, text='command:')
        label.grid(row=0, column=0, sticky=tk.E)

        self.servalcmd = tk.StringVar()
        # TODO:Dynamically modify text size on window resize
        entry = ttk.Entry(cmd_frame, textvariable=self.servalcmd, width=40)
        entry.grid(row=0, column=1, sticky=tk.W)
        runbtn = ttk.Button(cmd_frame, text='Run', default=tk.ACTIVE, command=self.cmd_run_servalcmd)
        runbtn.grid(row=0, column=2)


        # TEMP
        btn = ttk.Button(toolbar, text='rem peer', command=lambda :self.unregister_peer('abcd'))
        btn.grid(row=1, column=4)
        btn = ttk.Button(toolbar, text='add peer', command=lambda :self.register_peer('abcd'))
        btn.grid(row=1, column=3)
        #~ btn = ttk.Button(toolbar, text='List Keyring', command=self.cmd_ZZdujour)
        #~ btn.grid(row=0, column=5)
        #~ # --- Row 2 ----
        #~ btn = ttk.Button(toolbar, text='Self + Peers', command=self.cmd_show_peers)
        #~ btn.grid(row=1, column=0)
        #~ btn = ttk.Button(toolbar, text='Send Msg', command=self.cmd_send_message)
        #~ btn.grid(row=1, column=1)
        #~ btn = ttk.Button(toolbar, text='Show Msgs', command=self.cmd_show_messages)
        #~ btn.grid(row=1, column=2)
        
        toolbar.columnconfigure(3, weight=1)

        #entry.bind('<Return>', self.cmd_run_servalcmd)
        # Pressing Enter in the Entry should run the command
        entry.bind('<Return>', lambda e: runbtn.invoke())
        # Pressing Enter on the Run button should run the command
        runbtn.bind('<Return>', lambda e: runbtn.invoke())
        entry.focus()

        self.indicator['style'] = 'broken.ServaldFrame.TLabelframe'
        self.monitor_socket = None
        self.mysid = None
        self.peer = None
        try:
            self.servald = meshy.Servald(
                                    instancepath=DEFAULT_INSTANCEPATH,
                                    )
            try:
                res, out = self.servald.exec_cmd(['status'])
            except OSError:
                try:  # TODO:Cleaner implementation required
                    self.servald = meshy.Servald(
                                            instancepath=DEFAULT_INSTANCEPATH,
                                            binpath='./servald')
                    res, out = self.servald.exec_cmd(['status'])
                except OSError:
                    messagebox.showerror(
                        title='Cannot execute `servald`',
                        message='Cannot execute `servald`',
                        detail='The executable `servald` must be in your '
                            'PATH or in the current directory.',
                        icon='error',
                        )
                    res = 1

            parent['text'] = ' %s ' % self.servald.instancepath
                
            if res == 0:
                self.indicator['style'] = 'running.ServaldFrame.TLabelframe'
                self._init_monitor_socket(self.servald)
                ustwo = ['6DEEF513773A953FD9BAE28B30F854D90F3BF289644CD750F987C34E291D055A',
                    '33FE98B9ED39A0C87F37583E72ED51140A65AD68C0D12B4D90F118476202E657', # franny
                    #'B47FC3265250B31D86849AC1B2E4AF0D419604A30BD02223D491060619BB1014', # rover
                    ]
                mysid = list(self.servald.keyring)[0]
                print('Me:', mysid)
                self.mysid = mysid.hexsid
                ustwo.remove(self.mysid)
                self.peer = ustwo[0]
                print('Peer:%r'  % self.peer)

        except meshy.ServalError:
            self.main_obj.output('Unable to initialise serval. Please check '
                'the serval logs for details')

    """
    meshms list conversations [--keyring-pin=<pin>] [--entry-pin=<pin>]... <sid> [<offset>] [<count>]
       List MeshMS threads that include <sid>
    meshms list messages [--keyring-pin=<pin>] [--entry-pin=<pin>]... <sender_sid> <recipient_sid>
       List MeshMS messages between <sender_sid> and <recipient_sid>
    meshms read messages [--keyring-pin=<pin>] [--entry-pin=<pin>]... <sender_sid> [<recipient_sid>] [<offset>]
       Mark incoming messages from this recipient as read.
    meshms send message [--keyring-pin=<pin>] [--entry-pin=<pin>]... <sender_sid> <recipient_sid> <payload>
       Send a MeshMS message from <sender_sid> to <recipient_sid>

    """

    #~ def cmd_show_peers(self, *ign):
        #~ cmd = 'id self'
        #~ res, out = self.servald.exec_cmd(cmd.split())
        #~ #TODO:Get unicode output from meshy
        #~ out = out.decode('utf8')
        #~ self.main_obj.output('Exit code:{}\n{}'.format(res, out))
        #~ cmd = 'id peers'
        #~ res, out = self.servald.exec_cmd(cmd.split())
        #~ #TODO:Get unicode output from meshy
        #~ out = out.decode('utf8')
        #~ self.main_obj.output_w.insert('end', str(
                #~ 'Exit code:{}\n{}'.format(res, out)
                #~ ).encode('utf8'))

    def cmd_send_message(self, *ign):
        data = self.servalcmd.get().strip()
        cmd = 'meshms send message {} {}'.format(self.mysid, self.peer)
        cmd = cmd.strip().split() + [data]
        res, out = self.servald.exec_cmd(cmd)
        #TODO:Get unicode output from meshy
        out = out.decode('utf8')
        self.main_obj.output('Exit code:{}\n{}'.format(res, out))

    def cmd_show_messages(self, *ign):
        cmd = 'meshms list messages {} {}'.format(self.mysid, self.peer)
        res, out = self.servald.exec_cmd(cmd.split())
        #TODO:Get unicode output from meshy
        out = out.decode('utf8')
        self.main_obj.output('Exit code:{}\n{}'.format(res, out))

    def cmd_run_servalcmd(self, *ign):
        cmd = self.servalcmd.get().strip().split()
        res, out = self.servald.exec_cmd(cmd)
        #TODO:Get unicode output from meshy
        out = out.decode('utf8')
        self.main_obj.output('Exit code:{}\n{}'.format(res, out))

    def cmd_servald_status(self):
        res, out = self.servald.exec_cmd(['status'])
        #TODO:Get unicode output from meshy
        out = out.decode('utf8')
        self.main_obj.output('Exit code:{}\n{}'.format(res, out))

    def cmd_stop_servald(self, *ignore):
        res, out = self.servald.stop_running_daemon()
        if self.monitor_socket:
            self.monitor_socket.close()
        self.monitor_socket = None
        if res == 0:
            self.indicator['style'] = 'ServaldFrame.TLabelframe'
        else:
            self.indicator['style'] = 'broken.ServaldFrame.TLabelframe'
            self.main_obj.output('Exit code:{}\n{}'.format(res, out))

    def cmd_start_servald(self, *ignore):
        try:
            self.servald.start()
            self.indicator['style'] = 'running.ServaldFrame.TLabelframe'
            self._init_monitor_socket(self.servald)
        except meshy.ServalError:
            self.indicator['style'] = 'broken.ServaldFrame.TLabelframe'

    def _init_monitor_socket(self, servald):
        self.monitor_socket = servald.get_monitor_socket()
        mons = 'vomp rhizome peers dnahelper links interface'  # quit
        for mon in mons.split():
            self.monitor_socket.send('monitor {}\n'.format(mon).encode('utf8'))
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
                self._process_monitor_announcement(data)
            else:  # End of File. Remote closed
                self.monitor_socket.close()
                resched = False
        if resched:
            # Re-schedule ourselves
            self.parent.after(100, self.poll_monitor_socket)
        else:
            self.indicator['style'] = 'broken.ServaldFrame.TLabelframe'

    def register_peer(self, sid):
        logd('New Peer:%r', sid)
        self.main_obj.tree_obj.register_peer(sid)
        
    def unregister_peer(self, sid):
        logd('Peer disappeared:%r', sid)
        self.main_obj.tree_obj.unregister_peer(sid)

    def _process_monitor_announcement(self, buf):
        '''Parse and process output from a servald monitor.
        buf must be bytes'''
        #TODO:Don't assume entire message will appear in one call
        # 'INTERFACE:eth0:UP'
        # 'HANGUP:00f9a5'
        # call start:'CALLSTATUS:00f9a5:006ec1:6:2:0:6DEEF513773A953FD9BAE28B30F854D90F3BF289644CD750F987C34E291D055A:33FE98B9ED39A0C87F37583E72ED51140A65AD68C0D12B4D90F118476202E657:5551111:5553333'
        # call ended:'CALLSTATUS:00f9a5:006ec1:6:6:0:6DEEF513773A953FD9BAE28B30F854D90F3BF289644CD750F987C34E291D055A:33FE98B9ED39A0C87F37583E72ED51140A65AD68C0D12B4D90F118476202E657:5551111:5553333'
        for line in buf.split(b'\n'):
            if not line: continue
            if line.startswith(b'*'):
                logd('NEED TO READ SOME BYTES FROM MONITOR')  # BROKEN
                break
            elif line.startswith(b'MONITORSTATUS:'):
                continue
            elif line.startswith(b'LINK:'):
                logd('Monitor:LINK:%r', line)
            elif line.startswith(b'NEWPEER:'):
                self.register_peer(line[8:].decode('utf8'))
            elif line.startswith(b'OLDPEER:'):
                self.unregister_peer(line[8:].decode('utf8'))
            else:
                logd('Monitor received:%r', line)



class OutputTab(object):
    '''Draws and controls the Output tab'''
    def __init__(self, parent_notebook, main_obj):
        self.main_obj = main_obj
        self.parent_notebook = parent_notebook
        self.frame = ttk.Frame(parent_notebook)
        self.frame.pack(fill=tk.BOTH)
        parent_notebook.add(self.frame, text='Output')

        self.output_w = tk.Text(self.frame)
        self.output_w.grid(row=0, column=0, sticky=tk.NSEW)
        self.output_w.insert('1.0', 'Output will appear here.')

    def append_text(self, text):
        '''Append text to the contents of the output window'''
        self.output_w.insert('end', text)
        self.show()
        
    def replace_text(self, text):
        '''Replace the contents of the output window with supplied text'''
        self.output_w.delete('1.0', 'end')
        self.output_w.insert('1.0', text)
        self.show()
        
    def show(self):
        '''Show our tab'''
        self.parent_notebook.select(self.frame)



class PeerTab(object):
    '''Draws and controls the Peer tab'''
    def __init__(self, parent_notebook, main_obj):
        self.main_obj = main_obj
        self.parent_notebook = parent_notebook
        self.sid = None
        
        self.frame = ttk.Frame(parent_notebook)
        self.frame.pack(fill=tk.BOTH)
        parent_notebook.add(self.frame, text='Peer')
        self.label = ttk.Label(self.frame, text='None')
        self.label.grid(row=1, column=0)

    def show(self):
        '''Show our tab'''
        self.parent_notebook.select(self.frame)

    def switch_to_sid(self, sid):
        '''Display information for supplied sid'''
        logd('switch_to_sid:%r', sid)
        self.sid = sid
        self.label['text'] = sid
        self.show()



class TreeManager(object):
    '''Manages the TreeView'''
    # Naming items in treeview like peers.<SID>
    def __init__(self, parent, main_obj):
        self.main_obj = main_obj
        self.tree_w = ttk.Treeview(parent, columns=('sid'))#, height=30
        self.tree_w.grid(row=0, column=0, sticky=tk.NSEW)
        s = ttk.Scrollbar(parent, orient=tk.VERTICAL)#, command=listbox.yview)
        s.grid(row=0, column=1, sticky=tk.NS)
        #listbox.configure(yscrollcommand=s.set)

        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(0, weight=1)
        
        id1 = self.tree_w.insert('', 0, 'peers', text='Network Peers', open=True)
        #id2 = self.tree_w.insert('', 1, 'ab', text='Latest Subscriptions', open=True)
        #self.tree_w.insert(id1, 'end', text='First Sub')

        self.tree_w.bind('<<TreeviewSelect>>', self.cmd_select)

    def cmd_select(self, event):
        '''Figures out which item was clicked and invokes relevant
        functionality.'''
        itemid = self.tree_w.focus()
        logd('itemclicked %r', itemid)
        if itemid.startswith('peers.'):
            sid = itemid[6:]
            self.main_obj.peer_tab_obj.switch_to_sid(sid)

    def register_peer(self, sid):
        '''Show a new peer in the treeview'''
        try:
            self.tree_w.insert('peers', 'end', 'peers.%s' % sid,
                               text=sid[:10]+'*', values=(sid))
        except tk.TclError:
            self.tree_w.item('peers.%s' % sid, text=sid[:10]+'*')
        #self.main_obj.ttree.item(sid)['tags'] = 'disabled'
        logd('item %r', self.tree_w.item('peers.%s' % sid))

    def unregister_peer(self, sid):
        '''Show peer as no longer around'''
        self.tree_w.item('peers.%s' % sid, text='...%s*' % sid[:10])
        logd('item %r', self.tree_w.item('peers.%s' % sid))


    
# Functions ----------------------------------------------------------
#
logd = _logger.debug


def main(argv):
    logging.basicConfig(
                    format='%(asctime)s:%(name)s:%(levelname)s:%(message)s',
                    datefmt = '%H:%M:%S',
                    level=logging.DEBUG)
    root = tk.Tk()
    obj = MainWindow(root)
    root.mainloop()


if __name__ == '__main__':
    import sys
    main(sys.argv)

# Useful snippets:
# , borderwidth=10, relief='ridge'
# .pack(fill=tk.BOTH)
# logd('configure:%s', .configure())
