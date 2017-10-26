#!/usr/bin/env python
# -*- Encoding: utf-8 -*-
#
#  Python interface to the Serval mesh software
#
#  Copyright 2015-2017 Kevin Steen <ks@kevinsteen.net>
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

Full release at : https://github.com/skyguy/meshylib

Example usage
--------------

# Start and stop the Serval daemon (servald)

    import meshy
    servald = meshy.Servald(instancepath='~/serval')
    servald.start()
    print(servald.keyring)
    servald.stop_running_daemon()


Functions
----------

test_instance(...)
    Start a servald daemon process in ./test_instance. Returns a `Servald` instance


Classes
--------

Bundle
Rhizome
RhizomeResult
Servald

Exceptions (all derive from MeshyError)
-----------
RhizomeError
ServalError

'''
from __future__ import print_function, unicode_literals, division

import base64
import codecs
import io
import json
import logging
import os
import socket
import subprocess
try:  # Python 3
    import http.client as http
    from urllib.parse import urlencode
except ImportError:  # Python 2
    import httplib as http
    from urllib import urlencode

__version_info__ = 0, 2, 0

_logger = logging.getLogger(__name__)



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
        for header in headers:
            lkey = header[0].lower()
            if lkey.startswith(prefix):
                validident = lkey[len(prefix):].replace('-', '_')
                self.__dict__[validident] = header[1]
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
        # TODO: Use dict of format strings
        # NB:On a PartialBundle, only a few manifest fields are available
        result = ''
        if self.ispartial:
            result = '(P)'
        else:
            result = '(F)'
        service = self['service']
        if service == 'file':
            result += 'name:' + self['name']
        #~ elif service == 'meshforum':
            #~ logd('%s, %s, %s', type(result), type('forums:'), type(self.get('name', '')))
            #~ result += 'forums:' + self.get('name', '')
        elif service == 'meshy_test':
            result += 'version:%s, .inserttime:%r' % (
                self['version'], self['.inserttime'])
        elif service == 'MeshMS2' or service == 'MeshMS1':
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
            elif k == 'signatures':
                result = k + '=<{} bytes>'.format(len(self[k]))
            elif k == 'payload':
                if hasattr(self[k], 'len'):
                    result = k + '=<{} bytes>'.format(len(self[k]))
                else:  # Possibly a file-type object
                    result = k + '<file>'
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
        key = _makeu(key)  # Ensure dict keys are unicode
        super(PartialBundle, self).__setitem__(key, value)

    def __setitem__(self, key, value):
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

    def update_from_headers(self, iterable):
        '''Update this bundle from the supplied Rhizome HTTP headers
        '''
        prefix = 'serval-rhizome-bundle-'  # Must be lowercase
        for (key, value) in iterable:
            key = key.lower()
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
                self[newkey] = value

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
    '''Wrapper around a list of Bundles which produces a better display in
    interactive use.'''
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
            self[key] = bundle # Keep a reference to it
        return bundle

    def __repr__(self):
        result = [' #       id         |   service    |  size   |\n']
        for count, i in enumerate(self):
            result.append('{:>2} {:16}* {:15} {:>8} {:60}\n'
                          .format(count,
                                  i['id'][:16],
                                  i['service'][:15],
                                  i['filesize'],
                                  i.summary
                                 ))
        resstr = ''.join(result).encode('utf8')
        return resstr



class SID(object):
    '''Serval Identity
    Attributes:
        sid
        identity
        did
        name
    '''
    def __init__(self, sid=None, identity=None, did=None, name=None, mapping=None):
        if sid:
            self.sid = sid
            self.identity = identity
            self.did = did
            self.name = name
        else:
            self.sid = mapping['sid']
            self.identity = mapping['identity']
            self.did = mapping.get('did')
            self.name = mapping.get('name')
        if not self.name:
            self.name = '[sid:{}*]'.format(self.sid[:10])

    def __repr__(self):
        return 'SID(%r, identity=%r, did=%r, name=%r)' % (
               self.sid, self.identity, self.did, self.name)

    def __str__(self):
        return self.name


class Keyring(object):
    '''A list-like object representing a Serval keyring returned by
    Servald.get_keyring()
    Methods:
        create_SID
        lock (Not yet implemented)
    '''
    # URLS:
    # /restful/keyring/identities.json
    # /restful/keyring/add  params: pin
    # /restful/keyring/SID/set  params: pin, did, name
    # /restful/keyring/
    # returns: 200 + json, 404, 500
    def __init__(self, api, idlist):
        logd('Keyring.init idlist=%r', idlist)
        self._api = api
        self._SIDlist = []
        for d in idlist:
            self._SIDlist.append(SID(mapping=d))
            logd('Keyring.init adding sid:%s', d)

    def create_SID(self, pin=None):
        '''Create a new SID optionally protected by `pin`. Returns
        the SID created.'''
        params = {}
        if pin:
            params['pin'] = pin
        result = self._api.GET_json_simple('keyring/add', params)
        new_sid = result['identity']
        return SID(mapping=new_sid)

    def lock(self):
        '''Lock this keyring (forget the password)'''
        raise NotImplementedError

    def __getitem__(self, index):
        return self._SIDlist[index]

    def __iter__(self):
        return iter(self._SIDlist)

    def __len__(self):
        return len(self._SIDlist)

    def __repr__(self):
        return '\n'.join(repr(s) for s in self._SIDlist)


class REST_API(object):
    BASEPATH = '/restful/'
    DEFAULT_PORT = 4110
    def __init__(self, auth, port=None, timeout=None):
        self.port = port or self.DEFAULT_PORT
        self._user = auth[0]
        self._password = auth[1]
        self.timeout = timeout or 5
        val = bytearray(self._user + ':' + self._password, 'latin-1')
        self._auth_b64 = base64.b64encode(val)


    def GET(self, path, params=None):
        extra = ''
        if params:
            extra = '?' + urlencode(params)
        fullpath = self.BASEPATH + path + extra

        headers = dict(Authorization = b'Basic ' + self._auth_b64)

        conn = http.HTTPConnection('127.0.0.1', self.port, timeout=self.timeout)
        conn.request('GET', fullpath, headers=headers)#body, headers))
        resp = conn.getresponse()
        #~ print('Status:{} {}'.format(resp.status, resp.reason))
        #~ print('Headers: ', resp.getheaders())
        return resp

    def GET_json_list(self, path, params=None):
        '''Generator: Make a request to the Serval REST API and decode the
        returned JSON list into dict() objects.'''
        response = self.GET(path=path, params=params)
        if response.status != 200:
            raise RESTError('{} {}'.format(response.status, response.reason))
        reader = codecs.getreader('utf8')
        result = reader(response)
        return _decode_json(stream=result)

    def GET_json_simple(self, path, params=None):
        response = self.GET(path=path, params=params)
        reader = codecs.getreader('utf8')
        result = reader(response)
        return json.loads(''.join(result))


    def fetch_meshms_conversationlist(self, my_sid):
        """Generator which yields dictionaries describing ???
        """
        """
        {
        "header":["_id","my_sid","their_sid","read","last_message","read_offset"],
        "rows":[
        [0,"6DEEF513773A953FD9BAE28B30F854D90F3BF289644CD750F987C34E291D055A","B47FC3265250B31D86849AC1B2E4AF0D419604A30BD02223D491060619BB1014",false,70,0],
        [1,"6DEEF513773A953FD9BAE28B30F854D90F3BF289644CD750F987C34E291D055A","33FE98B9ED39A0C87F37583E72ED51140A65AD68C0D12B4D90F118476202E657",false,359,0],
        [2,"6DEEF513773A953FD9BAE28B30F854D90F3BF289644CD750F987C34E291D055A","B1CD48A9CA9EFC7F42C342E334856067DF131825D764E01D7E099F1961D5E372",true,0,0]
        ]
        }
        """
        path = 'meshms/{}/conversationlist.json'.format(my_sid)
        preheaders, results = self.GET_json_list(path)
        return results


    def fetch_meshms_messagelist(self, my_sid, their_sid):
        """Generator which yields dictionaries describing each message
        sent between my_sid and their_sid.
        """
        """
        {
        "read_offset":0,
        "latest_ack_offset":359,
        "header":["type","my_sid","their_sid","offset","token","text","delivered","read","timestamp","ack_offset"],
        "rows":[
        [">","6DEEF513773A953FD9BAE28B30F854D90F3BF289644CD750F987C34E291D055A","33FE98B9ED39A0C87F37583E72ED51140A65AD68C0D12B4D90F118476202E657",359,"75URvvotcxO38IKs078KaRc1iLbA-ee6YGkgEaZ167FnAQAAAAAAAA==","reboot",true,false,1453164547,null],
        ["<","6DEEF513773A953FD9BAE28B30F854D90F3BF289644CD750F987C34E291D055A","33FE98B9ED39A0C87F37583E72ED51140A65AD68C0D12B4D90F118476202E657",359,"VXe25OneON9Cuv6q10XFnItq4O0XwXsD9gUiv6nykIVnAQAAAAAAAA==","aaa",true,false,1453164345,null],
        ["ACK","6DEEF513773A953FD9BAE28B30F854D90F3BF289644CD750F987C34E291D055A","33FE98B9ED39A0C87F37583E72ED51140A65AD68C0D12B4D90F118476202E657",370,"VXe25OneON9Cuv6q10XFnItq4O0XwXsD9gUiv6nykIVbAQAAAAAAAA==",null,true,false,null,359],
        [">","6DEEF513773A953FD9BAE28B30F854D90F3BF289644CD750F987C34E291D055A","33FE98B9ED39A0C87F37583E72ED51140A65AD68C0D12B4D90F118476202E657",14,"75URvvotcxO38IKs078KaRc1iLbA-ee6YGkgEaZ167EOAAAAAAAAAA==","hiya franny",true,false,1452794995,null]
        ]
        }
        """
        #TODO: Tests for this function
        path = 'meshms/{}/{}/messagelist.json'.format(
                    my_sid, their_sid)
        logd('REST_API.fetch_meshms_messagelist %s %s' % (my_sid, their_sid))
        logd('REST_API.fetch_meshms_messagelist:%s' % path)
        try:
            preheaders, results = self.GET_json_list(path)
            return results
        except RESTError:
            return []

    def post_bundle(self, path, params):
        '''Send a POST request to the REST API. Returns the Response object
        params : list of (name, data, mimetype) tuples
        returns : httplib.HTTPResponse object
            (status, reason, getheaders(), read())
        '''
        fullpath = self.BASEPATH + path

        headers = dict(Authorization = b'Basic ' + self._auth_b64)
        # TODO: Ensure boundary string not in body
        headers['Content-Type'] = 'multipart/form-data; boundary=5ae0cd27dbf049998b659580e89cea48'

        body = bytearray()
        for name, data, mimetype in params:
            body += bytearray(
                '--5ae0cd27dbf049998b659580e89cea48\r\n' +
                'Content-Disposition: form-data; name="' + name + '"\r\n' +
                'Content-Type: ' + mimetype + '\r\n\r\n'
                , 'utf8' )
            if hasattr(data, 'read'):  # File?
                body.extend(data.read())
                body.extend(b'\r\n')
            else:
                if data:
                    body += data + b'\r\n'
                else:  # Empty
                    body += b'\r\n'
        body += b'--5ae0cd27dbf049998b659580e89cea48--\r\n'

        conn = http.HTTPConnection('127.0.0.1', self.port, timeout=self.timeout)
        #conn = http.HTTPConnection('httpbin.org', 80)
        #conn.set_debuglevel(255)
        conn.request('POST', fullpath, body=body, headers=headers)
        #conn.request('POST', '/post', body=body, headers=headers)
        resp = conn.getresponse()
        #~ print('Status:{} {}'.format(resp.status, resp.reason))
        #~ print('Headers: ', resp.getheaders())
        #~ print('Body: ', resp.read())
        return resp

    def __repr__(self):
        return ('REST_API(auth=(%r, REDACTED), port=%r, timeout=%r)' % (
                self._user, self.port, self.timeout))



class Rhizome(object):
    '''Interface to the Serval Rhizome functionality
    Rhizome(auth=(user, password), [RESTport])
    Iterating over this object produces a list of PartialBundles
    representing every Bundle in the Rhizome store.

    Attributes:
        bundles : list of all bundles in the Rhizome store
    Methods:
        find_bundles
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
    def __init__(self, auth=None, RESTport=None):
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
        return BundleList(self, self.find_bundles())

    def find_bundles(self, **filters):
        '''Generator which produces bundles matching ALL filters.
        Each filter is of the form : fieldname=value
        Supported fieldnames are those returned by the Rhizome REST call
        'bundlelist.json' '''
        headers, results=self._api.GET_json_list('rhizome/bundlelist.json')
        return BundleList(self,
            self._filter_bundles(
                source=results,
                template=filters)
            )

    def _filter_bundles(self, source, template):
        '''Workhorse for Rhizome.find_bundles'''
        #logd('_filter_bundles START. template=%r', template)
        for dic in source:
            #logd('_filter_bundles checking dic: %r %r', dic['service'], dic['name'])
            if not template or _matches_template(dic, template):
                #logd('_filter_bundles MATCHED dic:%r %r', dic['service'], dic['name'])
                partialbundle = self._create_bundle(dic)
                yield partialbundle

    def get_bundle_manifest(self, bundle):
        '''Return a full Bundle based on the supplied PartialBundle with
        all fields (except 'payload') retrieved from Rhizome
        '''
        #TODO: rename to get_bundle and accept a bundle or id
        #GET /restful/rhizome/BID.rhm
        if 'id' not in bundle:
            raise AttributeError('Need to supply a Bundle with an `id` key')
        path = 'rhizome/%s.rhm' % bundle['id']
        res = self._api.GET(path)
        if res.status == Rhizome.RESP_200_OK:
            #logd('CONTENT:\n %r', res.content)
            bundle = Bundle(bundle)
            bundle.update_from_headers(res.getheaders())
            bundle.update_from_manifest(res.read())
            return bundle
        else:
            raise RhizomeError(RhizomeResult(res.status, res.getheaders()))

    def get_bundle_payload_raw(self, bundle):
        '''Retrieve the payload from Rhizome and populate bundle.payload.
        Also returns bundle'''
        #GET /restful/rhizome/BID/raw.bin
        #logd('get_bundle_payload_raw:bundle:%r', bundle)
        if 'id' not in bundle:
            raise AttributeError('Need to supply a Bundle with an `id` key')
        path = 'rhizome/%s/raw.bin' % bundle['id']
        params = {}
        if 'secret' in bundle:
            params['secret'] = bundle['secret']
        res = self._api.GET(path, params=params)
        if res.status == Rhizome.RESP_200_OK:
            #logd('CONTENT:\n%r', repr(res.content))
            bundle.payload = res.read()
            return bundle
        else:
            raise RhizomeError(RhizomeResult(res.status, res.getheaders()))

    def insert_bundle(self, bundle):
        '''insert_bundle(bundle) - Insert a Bundle into the Rhizome store
        bundle is updated with any Rhizome-applied attributes, including
        the Bundle ID (id), Bundle Secret (secret), date, filehash,
        and inserttime
        Returns a RhizomeResult instance containing the result codes
        '''
        params = _get_post_bundle_params(bundle)
        #print('insert_bundle: params:%r', params)
        res = self._api.post_bundle(path='rhizome/insert', params=params)
        rhizome_result = RhizomeResult(http_status_code=res.status,
                                       headers=res.getheaders())
        if res.status == Rhizome.RESP_200_OK \
           or res.status == Rhizome.RESP_201_CREATED:
            bundle.update_from_headers(res.getheaders())
            bundle.update_from_manifest(res.read())
            return rhizome_result
        else:
            raise RhizomeError(rhizome_result)

    def _create_bundle(self, dic):
        try:
            del dic['.token']  # API artifact, not a bundle attribute
        except KeyError:
            pass
        return PartialBundle(dic)

    def __iter__(self):
        return self.bundles.__iter__()

    def __repr__(self):
        return ('Rhizome(auth=(%r, REDACTED), RESTport=%r)' %
            (self.auth[0], self.RESTport))



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
            The TCP port number to use to contact the REST API.
    Attributes:
        keyring  (read-only)
        RESTport (read-only)
            Updated during start() to indicate which port servald is
            actually listening on. You can change the port by calling
                config_set('rhizome.http.port', PORT)
            but this will only take effect after a restart of servald.
    Methods:
        config_set
        config_update
        exec_cmd
        get_monitor_socket
        get_rhizome
        get_REST_default_credentials
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
                 RESTport=None, system=False):
        logd('Servald.init start')
        if instancepath is None and system==False:
            raise ServalError(''
                'To access the default instance (instancepath=None) you '
                'must also supply the parameter: system=True \n'
                "To launch in the 'test_instance'' folder off the "
                'current working directory, use:\n'
                "    d=%s.test_instance()" % __name__
                )
        binpath = binpath or 'servald'
        self.binpath = os.path.expanduser(binpath)
        if instancepath:
            self.instancepath = os.path.abspath(os.path.expanduser(instancepath))
            if len(self.instancepath) > 74:
                raise ServalError(
                    'servald INSTANCEPATH may be too long to create socket '
                    'path. Please use a shorter instancepath.')
        if auth:
            self.auth = auth
        else:
            self.auth = self._create_auth()
        self.RESTport = RESTport
        self._api = REST_API(auth=self.auth, port=self.RESTport)

    def config_set(self, key, value):
        '''Set the servald configuration `key` to `value`. key and
        value must be strings.'''
        # Backwards naming to be consistent with the servald command-line
        arglist = ['config', 'set', key, value, 'sync']
        logd('config_set: arglist:%r', arglist)
        res, out = self.exec_cmd(arglist=arglist)
        if res not in (0, 1):
            msg = ('Servald.config_set failed with return code %s. arglist=%s'
                 'output:%s' % (res, arglist, out))
            loge(msg)
            raise ServalError(msg)

    def config_update(self, configdict):
        '''Update the servald configuration from a dictionary.'''
        arglist = ['config']
        for key, value in configdict.items():
            arglist.extend(['set', key, value])
        arglist.append('sync')
        logd('config_update: arglist:%r', arglist)
        res, out = self.exec_cmd(arglist=arglist)
        logd('Servald.config_update : res:%s', res)
        if res not in (0, 1):
            msg = ('Servald.config_update failed with return code %r. '
                'arglist=%r, servald output:%r' % (
                 res, arglist, out))
            loge(msg)
            raise ServalError(msg)

    def exec_cmd(self, arglist):
        '''Pass the arglist to this instance of servald and return both
        the return code and a bytestring of stdout+stderr.
        `servald` returns :
            0 on success if the server is running
            1 on success if the server is stopped
            255 on failure
        '''
        if isinstance(arglist, str):
            arglist = arglist.split()  # Split string on whitespace
        env = dict()
        for var in ['PATH', 'LD_LIBRARY_PATH']:
            if var in os.environ:
                env[var] = os.environ[var]
        if self.instancepath:
            env['SERVALINSTANCE_PATH'] = self.instancepath
        fullargs = [self.binpath] + arglist
        try:  # TODO:Possible to return stdout, stderr seperately?
            return 0, subprocess.check_output(args=fullargs,
                                       env=env,
                                       )#stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            return e.returncode, e.output

    def fetch_meshms_messagelist(self, my_sid, their_sid):
        return self._api.fetch_meshms_messagelist(my_sid=my_sid,
                                            their_sid=their_sid)

    def get_keyring(self, pin=None):
        if pin:
            params = {'pin': pin}
        else:
            params = None
        headers, idlist = self._api.GET_json_list('keyring/identities.json', params)
        return Keyring(
            api=self._api,
            idlist=idlist
            )

    def get_monitor_socket(self):
        '''Return a stream socket connected to this servald instance. Caller
        is responsible for closing the socket when done.'''
        # Monitor connection supports these monitors
        # (from monitor.c, monitor_set function)
        # vomp, rhizome, peers, dnahelper, links, quit, interface
        monitor_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock_addr = '\x00' + self.instancepath[1:] + '/monitor.socket'
        logd('Connecting to monitor socket:%r', sock_addr)
        try:
            monitor_socket.connect(sock_addr)
        except socket.error:
            sock_addr = self.instancepath + '/monitor.socket'
            logd('Connecting to monitor socket:%r', sock_addr)
            try:
                monitor_socket.connect(sock_addr)
            except socket.error:
                loge('get_monitor_socket:Unable to connect to monitor socket')
                raise ServalError('Unable to connect to monitor socket')
        return monitor_socket

    @property
    def id_self(self):
        '''Returns a SID object representing our own id, or None if we don't
        have one yet'''
        res, output = self.exec_cmd(['id', 'self'])
        output = output.decode('utf8')
        count, _, sid = output.split('\n')[:3]
        try:
            return SID(sid=sid)
        except TypeError:
            return None

    @property
    def keyring(self):
        return self.get_keyring()

    @staticmethod
    def parse_monitor_stream(buf):
        '''Parse output from the servald monitor stream. `buf` must be bytes
        Returns a tuple: (eventlist, buf)
        Where :
            buf contains data remaining after parsing fully-formed events
            eventlist is a list of tuples: (eventtype, data)
        eventtype is one of:
            'BINARY' : data = (header, data)
            'LINK'
            'NEWPEER' : data = hex representation of SID
            'OLDPEER' : data = hex representation of SID
            'UNKNOWN' : data = the line read from the monitor stream
        TODO: Not all Serval events are decoded
        '''
        # See serval-dna/monitor.c
        # 'INTERFACE:eth0:UP'
        # 'HANGUP:00f9a5'
        # call start:'CALLSTATUS:00f9a5:006ec1:6:2:0:6DEEF513773A953FD9BAE28B30F854D90F3BF289644CD750F987C34E291D055A:33FE98B9ED39A0C87F37583E72ED51140A65AD68C0D12B4D90F118476202E657:5551111:5553333'
        # call ended:'CALLSTATUS:00f9a5:006ec1:6:6:0:6DEEF513773A953FD9BAE28B30F854D90F3BF289644CD750F987C34E291D055A:33FE98B9ED39A0C87F37583E72ED51140A65AD68C0D12B4D90F118476202E657:5551111:5553333'
        eventlist = []
        logd('Monitor received:%r' % buf)
        while buf:
            try:
                line, buf = buf.split(b'\n', 1) # Py2 doesn't like maxsplit
            except ValueError:
                break
            if not line: continue
            logd('Monitor line:%r' % line)
            if line.startswith(b'*'):  # Binary data
                # Binary data. First int is # of bytes to read after the end
                # of the current line
                size, header = line[1:].split(b':', 1)
                try:
                    bytes_to_read = int(size)
                    logd('NEED TO READ %s BYTES FROM MONITOR' % bytes_to_read)
                    data = buf[:bytes_to_read]
                    buf = buf[bytes_to_read:]
                    eventlist.append( ('BINARY',(header,data)) )
                except (ValueError):
                    loge('Unknown Monitor event: %r', line)
            #~ elif line.startswith(b'MONITORSTATUS:'):
                #~ eventlist.append( ('MONITORSTATUS', line) )
            #~ elif line.startswith(b'LINK:'):
                #~ eventlist.append( ('LINK', line) )
            elif line.startswith(b'NEWPEER:'):
                eventlist.append( ('NEWPEER', line[8:].decode('utf8')) )
            elif line.startswith(b'OLDPEER:'):
                eventlist.append( ('OLDPEER', line[8:].decode('utf8')) )
            else:
                logi('Monitor received unknown line:%r', line)
                eventlist.append( ('UNKNOWN', line) )
        return (eventlist, buf)

    @property
    def rhizome(self):
        '''Returns the Rhizome instance for this servald'''
        return Rhizome(auth=self.auth, RESTport=self.RESTport)

    def start(self):
        '''Start the servald daemon, returning the Servald object if
        succesful. Raises ServalError on any error
        '''
        logd('Servald.start')
        try:
            res, out = self.exec_cmd(arglist=['start'])
        except OSError:
            raise ServalError('Unable to execute specified binpath:{}'
                        'servald return code:{} output:{}'
                          .format(self.binpath, res, out))
        if res in (0, self.STATUS_RUNNING):
            self._update_params(out.decode('utf8'))
            return self
        raise ServalError('Unknown return code ({}) from servald. '
            'Check the serval logs for more information. Output:{}'
            .format(res, out))

    def stop_running_daemon(self):  # long name for safety
        '''Request the serval daemon to stop running'''
        return self.exec_cmd(arglist=['stop'])

    # --- Context Manager implementation ------
    def __enter__(self):
        # Must return the object to be used with the 'as' clause
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        # Return True to suppress supplied exception.
        self.stop_running_daemon()

    # --- Internal functions ------------------
    def _create_auth(self):
        '''Returns the default credentials to access the REST API. This will
        be called automatically if you don't supply the auth parameter
        on Servald creation.'''
        #TODO: Generate a random password
        self.config_set('api.restful.users.meshy.password', 'meshy')
        return ('meshy', 'meshy')

    def __repr__(self):
        return ('Servald(instancepath=%r, binpath=%r, RESTport=%r)'
                % (self.instancepath, self.binpath, self.RESTport))

    def _update_params(self, servald_output):
        '''Update our attributes with values from servald output'''
        lines = servald_output.splitlines()
        for line in lines:
            key, value = line.split(':', 1)
            if key == 'http_port':
                logd('_update_params: set RESTport to %s', value)
                self.RESTport = int(value)
                break



# Exceptions ---------------------------------------------------------
#

class MeshyError(Exception):
    pass


class RhizomeError(MeshyError):
    '''Indicates a Rhizome-specific error'''
    #~ def __init__(self, rhizome_result):
        #~ self.rhizome_result = rhizome_result
    #~ def __str__(self):
        #~ return repr(self.rhizome_result)


class ServalError(MeshyError):
    pass


class RESTError(MeshyError):
    pass

# Internal Functions -------------------------------------------------
#

logd = _logger.debug
logi = _logger.info
logw = _logger.warning  # Default log output level
loge = _logger.error
logc = _logger.critical


DEBUG_HTTP = False
def _decode_json(stream):
    '''Decodes the JSON from a serval REST response.
    Returns a tuple of (headersdict, rows_generator) where:
    headersdict
        Is a dictionary of JSON name:value pairs which appear before the 'headers' line
    rows_generator
        Is a generator which yields dict objects decoded from the rest of the stream

    Closes the stream when finished.
    '''
    def decode_row_stream(stream, header, source):
        logd('decode_row_stream starting. header:%s' % header)
        done = False
        for line in stream:
            if DEBUG_HTTP: source += line
            #logd('line:%s' % line)
            if line == ']\n':  # Last line
                stream.close()
                #logd('decode_row_stream finished')
                return
            if line.endswith('\n'):
                line = line[:-1]
            if line.endswith(','):
                line = line[:-1]
            #logd('final line:%s' % line)
            row = json.loads(line)
            #logd('row:%s' % row)
            #logd('header:%s' % header)
            record = dict(zip(header, row))
            #logd('decode_row_stream: yielding object: %r', record)
            yield record

    #logd('decode_json starting.')
    source = ''
    prefix_dict = {}
    state = 'parse_prefix_headers' # then header_found, done
    line = ''
    try:
        line = next(stream)  # Skip initial '{'
        #logd('line:%s' % line)
        for line in stream:
            #logd('line:%s' % line)
            if DEBUG_HTTP: source += line
            if line.endswith('\n'):
                line = line[:-1]
            if line.endswith(','):
                line = line[:-1]
            row = json.loads('{' + line + '}')
            if state=='parse_prefix_headers':
                if 'header' in row:
                    state = 'header_found'
                    junk = next(stream)  # skip "rows":[
                    #logd('returning prefix_dict:%s' % prefix_dict)
                    return (prefix_dict, decode_row_stream(stream, row['header'], source))
                else:
                    prefix_dict.update(row)
    except StopIteration:
        loge('Premature end of JSON stream. state=%s\n' % state + source)
        raise ValueError('Invalid JSON stream')
    except Exception:
        loge('Exception:Unable to parse JSON stream. state=%s line=%s source:\n%s' %
            (state, repr(line), source))
        raise
    #Reaching here is an error
    loge('Unable to parse JSON stream. state=%s\n' % state + source)
    raise ValueError('Invalid JSON stream')


def _formatted_headers(dic):
    '''Pretty print a dictionary'''
    res = ''
    for i in sorted(dic):
        res += '%r: %r\n' % (i, dic[i])
    return res


def _get_post_bundle_params(bundle):
    '''Use bundle attributes to populate a list of parameters for a Rhizome
    REST API request'''
    params = []
    if hasattr(bundle, 'id'):
        params.append(('bundle-id', bundle.id, 'text/plain'))
    if hasattr(bundle, 'author'):
        params.append(('bundle-author', bundle.author, 'text/plain'))
    if hasattr(bundle, 'secret'):
        params.append(('bundle-secret', bundle.secret, 'text/plain'))

    if hasattr(bundle, 'filehash'): #BROKEN
        del bundle['filehash'] #Workaround insert bug in rhizome

    params.append(('manifest',
                    bundle.get_unsigned_manifest(),
                    bundle.manifest_content_type
                  ))
    #payload must be AFTER manifest.
    if hasattr(bundle, 'payload'):
        params.append(('payload', bundle.payload, bundle.payload_content_type))
    else:
        logd('_get_post_bundle_params: NO PAYLOAD attr')
    return params


# def _makeu(x) : Return unicode on Python 2 & 3
import sys
if sys.version_info < (3,):
    def _makeu(x):
        return x.decode('utf8')
else:
    def _makeu(x):
        return x


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

def test_instance(instancepath='test_instance', binpath='./servald'):
    '''Start a test instance of the serval daemon in the 'test_instance'
    directory, creating it if necessary. Uses './servald' executable
    All interfaces are enabled in the configuration.
    Parameters:
        instancepath : (optional)
            The directory to pass as SERVALINSTANCE_PATH to servald
        binpath : (optional)
            Path to the binary executable `servald`

    The returned instance can be used in a `with` statement as a
    Context Manager.
    '''
    servald = Servald(instancepath=instancepath, binpath=binpath)
    servald.config_update({
        'interfaces.0.match':'*',
        'interfaces.0.type': 'ethernet',
        })
    servald.start()
    return servald


# Main ---------------------------------------------------------------
#
if __name__ == '__main__':
    print("This is probably not the program you're looking for.")
    print('Try running `meshygui` instead.')
    print('Use `import meshy` to use this library')
