#!/usr/bin/env python
# -*- Encoding: utf-8 -*-
#
#  Python interface to the Serval mesh software
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
'''meshy.py - Python interface to the Serval mesh software

Full release at : https://github.com/skyguy/meshy

Example usage
--------------

# Start and stop the Serval daemon (servald)

    import meshy
    servald = meshy.start_servald()
    print(servald.status())
    servald.stop_running_daemon()

# Send a MeshMS to a telephone number

    import meshy
    servald = meshy.start_servald()
    recipient = servald.find_SID(DID='555-1234')
    print(recipient.SID, recipient.name)
    me = servald.find_SID()[0]
    conversation = servald.get_conversation(sender=me, recipient=recipient)
    conversation.send('Working late - will be home soon')


API is below, but X marks not-yet-implemented functionality


Functions
----------

start_servald(...)
    Start the servald daemon process. Returns a `Servald` instance


Classes
--------

Bundle
Rhizome
RhizomeResult
Servald

Exceptions
-----------
RhizomeError

'''
from __future__ import print_function, unicode_literals, division

__version__ = '0.1.0'

import base64
import codecs
import io
import json
import logging
import os
import subprocess
try:
    from urllib.request import urlopen, Request
    from urllib.parse import urlencode
except ImportError:
    from urllib2 import urlopen, Request
    from urllib import urlencode

_logger = logging.getLogger(__name__)

try:
    import requests
except ImportError:
    print('Unable to find `requests` module. Some features unavailable')

REST_DEFAULT_PORT = 4110


# Python 2/3 support hacks ##################
#
# def makeu(x) : Return unicode on Python 2 & 3
import sys
if sys.version_info < (3,):
    def makeu(x):
        return x.decode('utf8')
else:
    def makeu(x):
        return x
#~ # def unicode_to_str() : Convert unicode to str on Python 2 & 3
#~ #
#~ import sys
#~ if sys.version_info < (3,):
    #~ def unicode_to_str(x):
        #~ return x.encode('ascii')
#~ else:
    #~ def unicode_to_str(x):
        #~ return x



class RhizomeResult(object):
    '''Encapsulates all 3 result codes from a Rhizome operation.
    Attributes:
        http_status_code
        bundle_status_code
        bundle_status_message
        payload_status_code
        payload_status_message
    '''
    def __init__(self, http_status_code, headers):
        self.http_status_code = int(http_status_code)
        self.bundle_status_code = None
        self.bundle_status_message = ''
        self.payload_status_code = None
        self.payload_status_message = ''
        prefix = 'serval-rhizome-result-'
        for key in headers:
            lkey = key.lower()
            if lkey.startswith(prefix):
                validident = lkey[len(prefix):].replace('-', '_')
                self.__dict__[validident] = headers[key]
        if self.bundle_status_code:
            self.bundle_status_code = int(self.bundle_status_code)
        if self.payload_status_code:
            self.payload_status_code = int(self.payload_status_code)

    def __repr__(self):
        return ('<' + self.__class__.__name__ +
                ' HTTP:{http_status_code} '
                'bundle:{bundle_status_code}:{bundle_status_message} '
                'payload:{payload_status_code}:{payload_status_message}>'
                .format(**self.__dict__)
               )



class PartialBundle(dict):
    '''An incomplete bundle in the Rhizome.bundles list. Call
    Rhizome.get_bundle_manifest(PartialBundle) to populate the manifest
    and Rhizome.get_bundle_payload_raw(Bundle) to get the payload
    A PartialBundle only has the attributes which Rhizome operates on,
    no custom attributes.


    '''
    ispartial = True
    def __init__(self, mapping=None, **kwargs):
        self.payload = None
        self.signatures = None
        if mapping:
            for key, value in mapping.items():
                self.__setitem__(key, value)
        if kwargs:
            for key, value in kwargs.items():
                self.__setattr__(key, value)

    @property
    def summary(self):
        '''Short text summary of the bundle based on service type.
        '''
        # TODO: Add meshforum format
        # TODO: Use dict of format strings
        result = ''
        if self.ispartial:
            result = '(P)'
        else:
            result = '(F)'
        if self['service'] == 'file':
            result += 'name:' + self['name']
        elif self['service'] == 'meshy_test':
            result += 'version:%s, .inserttime:%r' % (
                self['version'], self['.inserttime'])
        elif self['service'] == 'MeshMS2' or self['service'] == 'MeshMS1':
            result += 'sender: %s*, recipient: %s*' % (
                self['sender'][:10], self['recipient'][:10])
        else:
            result += self.__repr__()
        return result

    def _shortened_vals(self, format='s'):
        '''Internal function to list a Bundle's attributes with known long
        values shortened
        Returns a unicode string'''
        for k in sorted(self):
            if self[k] is None:
                result = k + '=<None>'
            elif k in ['payload', 'signatures']:
                result = k + '=<{} bytes>'.format(len(self[k]))
            elif k in ['id', 'filehash', 'recipient', 'sender', 'secret']:
                result = k + "=<%s*>" % (self[k][:10])
            else:
                result = k + ('=%'+format) % self[k]
            if format != 's':
                result += ' %s:%s' % (type(k), type(self[k]))
            yield result

    def __repr__(self):
        return '< %s.__repr__:\n   %s >' % (
            self.__class__.__name__,
            '\n   '.join(self._shortened_vals(format='r'))
            )

    def __str__(self):
        return '< %s.__str__:\n   %s >' % (
            self.__class__.__name__,
            '\n   '.join(self._shortened_vals())
            )

    def __getattr__(self, key):
        try:
            return self[key]
        except KeyError:
            raise AttributeError('Unknown attribute: `{}` on PartialBundle. '
                'You may need to call Rhizome.get_bundle_manifest(...) '
                'to get the full manifest'
                .format(key))

    def __setattr__(self, key, value):
        key = makeu(key)
        super(PartialBundle, self).__setitem__(key, value)

    def __setitem__(self, key, value):
        #~ key = unicode_to_str(key)
        super(PartialBundle, self).__setitem__(key, value)



class Bundle(PartialBundle):
    '''Represents a Rhizome Bundle

    class Bundle(**kwargs)
    class Bundle(mapping, **kwargs)
    class Bundle(iterable, **kwargs)

    Attributes:
      payload
          bytes() or a read()-supporting object containing the raw bytes of
          the payload of the Bundle.
      id
          Generated by Rhizome when Rhizome.insert_bundle() is called.
      version
          version of this BundleID
      service
          selector to differentiate different bundle types
      secret
          secret key used to sign bundle
      signatures
          bytes of the manifest signature
    And other attributes as defined by Serval or other apps

    Methods:
      get_unsigned_manifest
          Returns a bytestring suitable to pass to Rhizome
      update_from_headers
          Use supplied HTTP headers to update the Bundle
      update_from_manifest
          Use a rhizome/manifest bytestring to update the Bundle

    '''
    manifest_content_type = 'rhizome/manifest; format=text+binarysig'
    payload_content_type = 'application/octet-stream'
    ispartial = False
    NON_MANIFEST_FIELDS = ('ispartial', 'author', 'payload', 'secret',
                           'signatures')
    def get_unsigned_manifest(self):
        '''Returns a UTF-8 encoded byte-string'''
        result = bytearray()
        for key in sorted(self):
            if key not in self.NON_MANIFEST_FIELDS:
                result += bytearray('%s=%s\n' % (key, self[key]),
                                    encoding='utf8')
        return result

    def update_from_headers(self, mapping):
        '''Update this bundle from the supplied Rhizome HTTP headers
        mapping keys should be `str`.
        '''
        prefix = 'serval-rhizome-bundle-'  # Must be lowercase
        for origkey in mapping:
            key = origkey.lower()
            if key == prefix + 'name':
                continue  # Rhizome won't generate a name
            if key == prefix + 'rowid':
                continue  # Ignore artefact from REST API
            if key.startswith(prefix):
                #~ try:
                    #~ print('UPDATING %s from %s TO %s'
                    #~       % (k[22:], self[k[22:]], h[k]))
                #~ except KeyError :
                    #~ print('UPDATING %s from <MISSING> TO %s'
                    #~       % (k[22:], h[k]))
                newkey = key[len(prefix):].lower()
                self[newkey] = mapping[origkey]

    def update_from_manifest(self, manifest):
        '''Update this bundle by decoding the text+binarysig manifest'''
        fields, signatures = manifest.split(b'\x00', 1)
        self.signatures = signatures
        for line in fields.splitlines():
            key, value = line.split(b'=')
            key = key.decode('ascii')  # field names must be ascii
            value = value.decode('utf8')
            self[key] = value
        return self

    def __getattr__(self, key):
        try:
            return super(Bundle, self).__getitem__(key)
        except KeyError:
            raise AttributeError("Bundle has no field '%s'" % key)



class BundleList(list):
    def __init__(self, storage, *args):
        super(BundleList, self).__init__(*args)
        self.storage = storage

    def append(self, bundle):
        self.storage.insert_bundle(bundle)
        super(BundleList, self).append(bundle)
        #append returns nothing

    def __getitem__(self, key):
        #Use the PartialBundle to retrieve a Bundle
        bundle = super(BundleList, self).__getitem__(key)
        if bundle.ispartial:
            bundle = self.storage.get_bundle_manifest(bundle)
            self[key] = bundle #Might as well keep a reference to it
        return bundle

    def __repr__(self):
        result = [' #       id         |   service    |  size   |\n']
        for count, i in enumerate(self):
            #if count != 0 : break
            #print('BUNDLELIST REPR:',repr(i))
            result.append('{:>2} {:16}* {:15} {:>8} {:60}\n'
                          .format(count,
                                  i['id'][:16],
                                  i['service'][:15],
                                  i['filesize'],
                                  i.summary
                                 ))
        resstr = ''.join(result).encode('utf8')
        return resstr

    def __str__(self):
        return '__str__ on BundleList'


class REST_API(object):
    '''REST_API
    '''
    # Warning: The requests.headers are `str`, thus different on Python2/3
    # TODO: Return RhizomeResponse or raise RhizomeError from relevant methods
    _APIREALM = 'Serval RESTful API'
    def __init__(self, auth, port=REST_DEFAULT_PORT, timeout=5):
        self._baseurl = 'http://127.0.0.1:{}/restful/'.format(port)
        #self._baseurl = 'http://httpbin.org/post'
        self._user = auth[0]
        self._password = auth[1]
        self.timeout = timeout

    def GET(self, path, params=None, data=None):
        url = self._baseurl + path
        logd('REST_API.GET: url:%s', url)
        res = requests.get(url=url,
                           timeout=self.timeout,
                           data=data,
                           params=params,
                           auth=(self._user, self._password),
                          )
        return res

    def GET_json_list(self, path, params=None):
        '''Make a request to the Serval REST API expecting a JSON list
        result'''
        data = ''
        if params:
            data = '?' + urlencode(params)
        fullurl = self._baseurl + path + data
        request = Request(fullurl)
        val = bytearray(self._user + ':' + self._password, 'utf8')
        request.add_header('Authorization', b'Basic ' + \
            base64.b64encode(val))

        logd('REST_API.GET_json_list: url:%s', fullurl)
        response = urlopen(request, timeout=self.timeout)
        logd('GET_json_list: response:{}, getcode():{}, info():{}'
             .format(response, response.getcode(), response.info()))
        reader = codecs.getreader('utf8')
        result = reader(response)
        return _decode_rhizome_json_list(stream=result)

    def post_bundle(self, path, params):
        '''Send a POST request to the REST API. Returns the Response object'''
        url = self._baseurl + path
        logd('REST_API.POST: url:%s', url)
        res = requests.post(url=url,
                            files=params,
                            timeout=self.timeout,
                            auth=(self._user, self._password),
                           )
        return res



class Rhizome(object):
    '''Interface to the Serval Rhizome functionality
    Rhizome(auth=(user, password), [RESTport])
    Attributes:
        bundles : list of bundles
        SIDlist : set of Serval IDs
    Methods:
        fetch_bundles
            List bundles, optionally filtered
        get_bundle_manifest
            get the full manifest of a bundle
        get_bundle_payload_raw
            get the un-decoded payload of a bundle
        insert_bundle(bundle)
            insert a bundle and update its attributes

    '''
    #Response Codes:
    RESP_200_OK = 200
    RESP_201_CREATED = 201
    RESP_202_ACCEPTED = 202
    def __init__(self, auth=None, RESTport=REST_DEFAULT_PORT):
        if auth is None:
            raise RuntimeError(
                '\n\n'
                '  usage: Rhizome(auth=(username, password))\n\n'
                'The REST API requires authentication. For testing purposes '
                'you can create a valid username/password combination by '
                'adding a line like this to your `serval.conf` file :\n\n'
                '  api.restful.users.TESTUSERNAME.password=TESTPASSWORD\n')
        self.auth = auth
        self.RESTport = RESTport
        self._api = REST_API(auth=auth, port=RESTport)

    @property
    def bundles(self):
        bundlelist = list(self.fetch_bundles())
        rhizome = self
        return BundleList(rhizome, bundlelist)

    def fetch_bundles(self, **filters):
        '''Generator which produces bundles matching ALL filters.
        Each filter is of the form : fieldname=value
        Supported fieldnames are those returned by the Rhizome REST call
        'bundlelist.json' '''
        return self._filter_bundles(
            source=self._api.GET_json_list('rhizome/bundlelist.json'),
            template=filters)

    def _filter_bundles(self, source, template):
        '''Workhorse for Rhizome.fetch_bundles'''
        #logd('_filter_bundles START. template=%r', template)
        for dic in source:
            #logd('_filter_bundles checking dic: %r %r', dic['service'], dic['name'])
            if not template or _matches_template(dic, template):
                #logd('_filter_bundles MATCHED dic:%r %r', dic['service'], dic['name'])
                partialbundle = self._create_bundle(dic)
                yield partialbundle
            #logd('')
        #logd('_filter_bundles DONE')

    def get_bundle_manifest(self, bundle):
        '''Return the supplied Bundle with fields updated from Rhizome
        '''
        #TODO: rename to get_bundle and accept a bundle or id
        #GET /restful/rhizome/BID.rhm
        if 'id' not in bundle:
            raise AttributeError('Need to supply a Bundle with an `id` key')
        path = 'rhizome/%s.rhm' % bundle['id']
        res = self._api.GET(path)
        if res.status_code == Rhizome.RESP_200_OK:
            #logd('CONTENT:\n %r', res.content)
            bundle = Bundle(bundle)
            bundle.update_from_headers(res.headers)
            bundle.update_from_manifest(res.content)
            return bundle
        else:
            print('GET_BUNDLE_MANIFEST FAILED. STATUS:', res.status_code)
            print('CONTENT:\n', repr(res.content))
            print('SENT REQUEST HEADERS:', res.request.headers)
            print('SENT REQUEST BODY:', res.request.body)
            res.raise_for_status()

    def get_bundle_payload_raw(self, bundle):
        '''Retrieve the payload from Rhizome and populate bundle.payload.
        Also returns bundle'''
        #GET /restful/rhizome/BID/raw.bin
        #logd('get_bundle_payload_raw:bundle:%r', bundle)
        if 'id' not in bundle:
            raise AttributeError('Need to supply a Bundle with an `id` key')
        path = 'rhizome/%s/raw.bin' % bundle['id']
        data = {}
        if 'secret' in bundle:
            data['secret'] = bundle['secret']
        res = self._api.GET(path, data=data)
        if res.status_code == Rhizome.RESP_200_OK:
            #logd('CONTENT:\n%r', repr(res.content))
            bundle.payload = res.content
            return bundle
        else:
            print('GET_BUNDLE_PAYLOAD FAILED. STATUS:', res.status_code)
            print('CONTENT:\n', repr(res.content))
            print('SENT REQUEST HEADERS:', res.request.headers)
            print('SENT REQUEST BODY:', res.request.body)
            res.raise_for_status()

    def insert_bundle(self, bundle):
        '''insert_bundle(bundle) - Insert a Bundle into the Rhizome store
        bundle is updated with any Rhizome-applied attributes, including
        the Bundle ID (id), Bundle Secret (secret), date, filehash,
        and inserttime
        '''
        params = _get_post_bundle_params(bundle)
        #logd('insert_bundle: params:%r', params)
        res = self._api.post_bundle(path='rhizome/insert', params=params)
        rhizome_result = RhizomeResult(http_status_code=res.status_code,
                                       headers=res.headers)
        #~ print('Rhizome result:', rhizome_result)
        #~ print('REQUEST HEADERS:', res.request.headers)
        #~ print('REQUEST BODY:', res.request.body)
        #~ print('RESULT HEADERS:\n' + _formatted_headers(res.headers))
        #~ print('RESULT BODY:\n', repr(res.content))
        if res.status_code == Rhizome.RESP_200_OK \
           or res.status_code == Rhizome.RESP_201_CREATED:
            bundle.update_from_headers(res.headers)
            bundle.update_from_manifest(res.content)
            return rhizome_result
        else:
            print('INSERT_BUNDLE FAILED. STATUS:', res.status_code)
            print('Rhizome result:', rhizome_result)
            print('REQUEST HEADERS:', res.request.headers)
            print('REQUEST BODY:', res.request.body)
            print('RESULT HEADERS:\n' + _formatted_headers(res.headers))
            print('RESULT BODY:\n', repr(res.content))
            raise RhizomeError(rhizome_result)

    def _create_bundle(self, dic):
        try:
            del dic['.token']  # API artifact, not a bundle attribute
        except KeyError:
            pass
        return PartialBundle(dic)



class RhizomeError(Exception):
    '''Indicates a Rhizome-specific error'''
    def __init__(self, rhizome_result):
        self.rhizome_result = rhizome_result
    def __repr__(self):
        return str(self.rhizome_result)



class Servald(object):
    '''A single instance of a Serval daemon (servald)

    Servald([instancepath], [binpath], [auth], [RESTport])
    The instance will not be started automatically, use start() when needed.
    Parameters:
        instancepath : (Optional)
            Directory to use as base directory for all files and
            subdirectories. If not supplied, servald will use it's own
            defaults.
        binpath : (Optional)
            The path to the servald binary. If not supplied, searches the
            system PATH for 'servald'.
        auth : (Optional)
            A (username, password) tuple to use as authorisation when
            accessing the REST API.
        RESTport : int (Optional)
            The TCP port number to use for the REST API. If the daemon is
            already running, the port number change may not take effect
            until the next time the daemon is started.
    Methods:
        config_set
        config_update
        exec_cmd
        start
        stop_running_daemon

    Errors:
        Raises ServalError if executing `binpath` fails, or serval cannot
        start for any reason.
        
    The Servald object can also be used in a `with` statement:
        with Servald().start() as servald:
            print(servald.keyring)

    WARNING:This will stop the daemon when you're done, even if it was
    already running when your code started.

    Note: When testing between two PCs, you need to set the interface
    type to ethernet to get serval to use the interface: E.g.:
        Servald.config_update({'interfaces.0.match': 'eth1',
                               'interfaces.0.type': 'ethernet'})

    '''
    STATUS_RUNNING = 10
    def __init__(self, instancepath=None, binpath=None, auth=None,
                 RESTport=None):
        self.binpath = os.path.expanduser(binpath or 'servald')
        self.instancepath = os.path.expanduser(instancepath or '')

        if self.instancepath and self.instancepath[0] != '/':
            self.instancepath = os.path.join(os.getcwd(), self.instancepath)
        config = {}

        if auth is None:
            #TODO: Generate a random password
            config['api.restful.users.test.password'] = 'testpass'
            auth = ('test', 'testpass')
        self.auth = auth

        if RESTport is None:
            self.RESTport = REST_DEFAULT_PORT
        else:
            self.RESTport = RESTport
            config['rhizome.http.port'] = str(RESTport)

        self._api = REST_API(auth=auth, port=RESTport)
        if config:
            if not self.config_update(config):
                raise ServalError('Unable to set initial configuration')

    @property
    def keyring(self):
        return list(self._api.GET_json_list('keyring/identities.json'))

    def exec_cmd(self, arglist):
        '''Pass the arglist to this instance of servald and return both
        the return code and a string of stdout+stderr
        '''
        env = dict()
        env['PATH'] = os.environ['PATH']
        if self.instancepath:
            env['SERVALINSTANCE_PATH'] = self.instancepath
        fullargs = [self.binpath] + arglist
        try:
            return 0, subprocess.check_output(args=fullargs,
                                       env=env,
                                       stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            loge('exec_cmd failed: exitcode:{} '
                 'cmd:{}'.format(e.returncode, e.cmd))
            return e.returncode, e.output

    def get_rhizome(self):
        '''Returns the Rhizome instance for this servald'''
        return Rhizome(auth=self.auth, RESTport=self.RESTport)

    def start(self):
        '''Start the servald daemon, returning the Servald object if
        succesful. Raises ServalError on any error
        '''
        #TODO:Parse startup for port numbers
        logd('Servald.start')
        try:
            self.exec_cmd(arglist=['start'])
        except subprocess.CalledProcessError as exc:
            if exc.returncode == self.STATUS_RUNNING:
                return self
            raise ServalError('Unable to start servald. Check the serval '
                    'logs for more information')
        except OSError:
            raise ServalError('Unable to execute specified binpath:{}'
                          .format(self.binpath))
        return self

    def stop_running_daemon(self):  # long name for safety
        '''Request the serval daemon to stop running'''
        return self.exec_cmd(arglist=['stop'])

    def config_set(self, key, value):
        '''Set the servald configuration `key` to `value`. key and
        value must be strings.'''
        # Backwards naming to be consistent with the servald command-line
        arglist = ['config', 'set', key, value]
        logd('config_set: arglist:%r', arglist)
        return self.exec_cmd(arglist=arglist)

    def config_update(self, configdict):
        '''Update the servald configuration from a dictionary. Returns
        True on success, False otherwise'''
        arglist = ['config']
        for key, value in configdict.items():
            arglist.extend(['set', key, value])
        logd('config_update: arglist:%r', arglist)
        try:
            self.exec_cmd(arglist=arglist)
        except subprocess.CalledProcessError as e:
            loge('Servald.config_update FAILED:retcode:{}, config:{}'
                .format(e.returncode, configdict))
            return False
        return True


    # --- Context Manager implementation ------
    def __enter__(self):
        # Must return the object to be used with the 'as' clause
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        # Return True to suppress supplied exception.
        self.stop_running_daemon()



class ServalError(Exception):
    pass


# Internal Functions -------------------------------------------------
#
def logd(msg, *args, **kwargs):
    '''log args at level `Debug`'''
    _logger.debug(msg, *args, **kwargs)


def logw(msg, *args, **kwargs):
    '''Log args at level `Warning`'''
    _logger.warn(msg, *args, **kwargs)


def loge(msg, *args, **kwargs):
    '''Log args at level `Error`'''
    _logger.error(msg, *args, **kwargs)


def _decode_rhizome_json_list(stream):
    '''Generator which yields dict objects decoded from the supplied
    unicode stream in Serval's REST response format. Closes the stream when
    finished.
    '''
    try:
        line = next(stream)  # skip first line '{\n'
        line = next(stream)
    except StopIteration:
        raise ValueError('Empty Rhizome JSON list')
    decoded = json.loads('{' + line[:-2] + '}')
    try:
        headers = decoded['header']
    except KeyError:
        raise ValueError('Could not decode header line.')
    line = next(stream)  # skip line
    for line in stream:
        if line == ']\n':  # Last line
            stream.close()
            return
        if line.endswith(',\n'):
            data = line[:-2]
        else:
            data = line[:-1]
        try:
            row = json.loads(data)
        except ValueError:
            raise ValueError('Could not decode row:{}'.format(line))
        record = dict(zip(headers, row))
        yield record
    # If we reach here, it's an error
    raise ValueError('No Rhizome JSON list found')


def _formatted_headers(dic):
    '''Pretty print a dictionary'''
    res = ''
    for i in sorted(dic):
        res += '%r: %r\n' % (i, dic[i])
    return res


def _get_post_bundle_params(bundle):
    '''Use bundle attributes to populate a dict of parameters for a Rhizome
    REST API request'''
    params = []
    if hasattr(bundle, 'id'):
        params.append(('bundle-id', (None, bundle.id, 'text/plain')))
    if hasattr(bundle, 'author'):
        params.append(('bundle-author',
                       (None, bundle.author, 'text/plain')))
    if hasattr(bundle, 'secret'):
        params.append(('bundle-secret', (None, bundle.secret, 'text/plain')))

    if hasattr(bundle, 'filehash'): #BROKEN
        del bundle['filehash'] #Workaround insert bug in rhizome

    params.append(('manifest',
                   (None, io.BytesIO(bundle.get_unsigned_manifest()),
                    bundle.manifest_content_type)
                  )
                 )
    #payload must be AFTER manifest.
    if hasattr(bundle, 'payload'):
        if bundle.payload is None:
            logd('_get_post_bundle_params: PAYLOAD is None')
            params.append(('payload',
                           (None, '', bundle.payload_content_type)))
        else:
            if not hasattr(bundle.payload, 'read'):
                iopayload = io.BytesIO(bundle.payload)
            params.append(('payload',
                           (None, iopayload, bundle.payload_content_type)))
    else:
        logd('_get_post_bundle_params: NO PAYLOAD attr')
    return params


def _matches_template(mapping, template):
    '''Returns true if `template` is empty, or if the fields and values of
    `mapping` match ALL fields and values in `template`'''
    #logd('_matches_template START')
    for field, value in template.items():
        try:
            #logd('_matches_template checking field:', field)
            if mapping[field] != value:
                #logd('_matches_template MISMATCH. Returning')
                return False
        except KeyError:  # Key missing
            raise KeyError('Invalid filter field:' + field)
    #logd('_matches_template DONE')
    return True


# Public Functions ---------------------------------------------------
#
def start_servald(instancepath=None, binpath=None):
    '''Start the servald daemon binary and return a Servald instance
    Parameters:
        instancepath : (optional)
            The directory to pass as SERVALINSTANCE_PATH to servald
        binpath : (optional)
            Path to the binary executable `servald`

    The returned instance can be used in a `with` statement as a
    Context Manager.
    '''
    servald = Servald(instancepath=instancepath, binpath=binpath)
    servald.start()
    return servald


# Main ---------------------------------------------------------------
#
if __name__ == '__main__':
    print('Use `import meshy` to use this library')