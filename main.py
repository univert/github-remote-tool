#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys, json, base64, time, re, logging, os
from argparse import ArgumentParser
from functools import partial, update_wrapper, lru_cache
from http.client import HTTPConnection, HTTPSConnection
from types import SimpleNamespace
from urllib.parse import urlencode, urlsplit
from random import randint

_default_headers = {
    'user-agent': 'github_client',
    'content-type': 'application/json'
}

class API(object):
    """
    The toplevel object, and the "entry-point" into the client API.
    Subclass this to develop an application for a particular REST API.

    Model your __init__ after the GitHub example.
    """
    def __init__(self, *args, **kwargs):
        raise Exception(
            'Please subclass API and override __init__() to '
            'provide a ConnectionProperties object. See the GitHub '
            'class for an example'
        )

    def setClient(self, client):
        self.client = client

    def setConnectionProperties(self, props):
        self.client.setConnectionProperties(props)

    def __getattr__(self, key):
        return IncompleteRequest(self.client).__getattr__(key)
    __getitem__ = __getattr__

    def __repr__(self):
        return IncompleteRequest(self.client).__repr__()

    def getheaders(self):
        return self.client.headers


class IncompleteRequest(object):
    """
    IncompleteRequests are partially-built HTTP requests.
    They can be built via an HTTP-idiomatic notation,
    or via "normal" method calls.

    Specifically,
    >>> IncompleteRequest(client).path.to.resource.METHOD(...)
    is equivalent to
    >>> IncompleteRequest(client).client.METHOD('path/to/resource', ...)
    where METHOD is replaced by get, post, head, etc.

    Also, if you use an invalid path, too bad. Just be ready to handle a
    bad status code from the upstream API. (Or maybe an
    httplib.error...)

    You can use item access instead of attribute access. This is
    convenient for using variables\' values and is required for numbers.
    >>> GitHub('user','pass').whatever[1][x][y].post()

    To understand the method(...) calls, check out github.client.Client.
    """
    def __init__(self, client, url=''):
        self.client = client
        self.url = url

    def __getattr__(self, key):
        if key in self.client.http_methods:
            htmlMethod = getattr(self.client, key)
            wrapper = partial(htmlMethod, url=self.url)
            return update_wrapper(wrapper, htmlMethod)
        else:
            return IncompleteRequest(self.client, self.url + '/' + str(key))

    __getitem__ = __getattr__

    def __str__(self):
        return self.url

    def __repr__(self):
        return '%s: %s' % (self.__class__, self.url)


class Client(object):
    http_methods = (
        'head',
        'get',
        'post',
        'put',
        'delete',
        'patch',
    )

    default_headers = {}
    headers = None

    def __init__(self, username=None, password=None, token=None,
                 connection_properties=None):
        self.prop = None

        # Set up connection properties
        if connection_properties is not None:
            self.setConnectionProperties(connection_properties)

    def setConnectionProperties(self, prop):
        """
        Initialize the connection properties. This must be called
        (either by passing connection_properties=... to __init__ or
        directly) before any request can be sent.
        """
        if type(prop) is not ConnectionProperties:
            raise TypeError(
                "Client.setConnectionProperties: "
                "Expected ConnectionProperties object"
            )

        if prop.extra_headers is not None:
            prop.filterEmptyHeaders()
            self.default_headers = _default_headers.copy()
            self.default_headers.update(prop.extra_headers)
        self.prop = prop

        # Enforce case restrictions on self.default_headers
        tmp_dict = {}
        for k, v in self.default_headers.items():
            tmp_dict[k.lower()] = v
        self.default_headers = tmp_dict

    def head(self, url, headers=None, **params):
        headers = headers or {}
        url += self.urlencode(params)
        return self.request('HEAD', url, None, headers)

    def get(self, url, headers=None, **params):
        headers = headers or {}
        url += self.urlencode(params)
        return self.request('GET', url, None, headers)

    def post(self, url, body=None, headers=None, **params):
        headers = headers or {}
        url += self.urlencode(params)
        if 'content-type' not in headers:
            headers['content-type'] = 'application/json'
        return self.request('POST', url, body, headers)

    def put(self, url, body=None, headers=None, **params):
        headers = headers or {}
        url += self.urlencode(params)
        if 'content-type' not in headers:
            headers['content-type'] = 'application/json'
        return self.request('PUT', url, body, headers)

    def delete(self, url, headers=None, **params):
        headers = headers or {}
        url += self.urlencode(params)
        return self.request('DELETE', url, None, headers)

    def patch(self, url, body=None, headers=None, **params):
        """
        Do a http patch request on the given url with given body,
        headers and parameters.
        Parameters is a dictionary that will will be urlencoded
        """
        headers = headers or {}
        url += self.urlencode(params)
        if 'content-type' not in headers:
            headers['content-type'] = 'application/json'
        return self.request('PATCH', url, body, headers)

    def request(self, method, url, bodyData, headers):
        """
        Low-level networking. All HTTP-method methods call this
        """

        headers = self._fix_headers(headers)
        url = self.prop.constructUrl(url)

        if bodyData is None:
            # Sending a content-type w/o the body might break some
            # servers. Maybe?
            if 'content-type' in headers:
                del headers['content-type']

        # TODO: Context manager
        requestBody = RequestBody(bodyData, headers)
        conn = self.get_connection()
        conn.request(method, url, requestBody.process(), headers)
        response = conn.getresponse()
        status = response.status
        content = ResponseBody(response)
        self.headers = response.getheaders()

        conn.close()
        return status, content.processBody()

    def _fix_headers(self, headers):
        # Convert header names to a uniform case
        tmp_dict = {}
        for k, v in headers.items():
            tmp_dict[k.lower()] = v
        headers = tmp_dict

        # Add default headers (if unspecified)
        for k, v in self.default_headers.items():
            if k not in headers:
                headers[k] = v
        return headers

    def urlencode(self, params):
        if not params:
            return ''
        return '?%s' % urlencode(params)

    def get_connection(self):
        if self.prop.secure_http:
            conn = HTTPSConnection(self.prop.api_url)
        elif self.prop.extra_headers is None \
                or 'authorization' not in self.prop.extra_headers:
            conn = HTTPConnection(self.prop.api_url)
        else:
            raise ConnectionError(
                'Refusing to send the authorization header over an '
                'insecure connection.'
            )

        return conn


class Body(object):
    """
    Superclass for ResponseBody and RequestBody
    """
    def parseContentType(self, ctype):
        """
        Parse the Content-Type header, returning the media-type and any
        parameters
        """
        if ctype is None:
            self.mediatype = 'application/octet-stream'
            self.ctypeParameters = {'charset': 'ISO-8859-1'}
            return

        params = ctype.split(';')
        self.mediatype = params.pop(0).strip()

        # Parse parameters
        if len(params) > 0:
            params = map(lambda s: s.strip().split('='), params)
            paramDict = {}
            for attribute, value in params:
                # TODO: Find out if specifying an attribute multiple
                # times is even okay, and how it should be handled
                attribute = attribute.lower()
                if attribute in paramDict:
                    if type(paramDict[attribute]) is not list:
                        # Convert singleton value to value-list
                        paramDict[attribute] = [paramDict[attribute]]
                    # Insert new value along with pre-existing ones
                    paramDict[attribute] += value
                else:
                    # Insert singleton attribute value
                    paramDict[attribute] = value
            self.ctypeParameters = paramDict
        else:
            self.ctypeParameters = {}

        if 'charset' not in self.ctypeParameters:
            self.ctypeParameters['charset'] = 'ISO-8859-1'
            # NB: INO-8859-1 is specified (RFC 2068) as the default
            # charset in case none is provided

    def mangled_mtype(self):
        """
        Mangle the media type into a suitable function name
        """
        return self.mediatype.replace('-', '_').replace('/', '_')


class ResponseBody(Body):
    """
    Decode a response from the server, respecting the Content-Type field
    """
    def __init__(self, response):
        self.response = response
        self.body = response.read()
        self.parseContentType(self.response.getheader('Content-Type'))
        self.encoding = self.ctypeParameters['charset']

    def decode_body(self):
        """
        Decode (and replace) self.body via the charset encoding
        specified in the content-type header
        """
        self.body = self.body.decode(self.encoding)

    def processBody(self):
        """
        Retrieve the body of the response, encoding it into a usuable
        form based on the media-type (mime-type)
        """
        handlerName = self.mangled_mtype()
        handler = getattr(self, handlerName, self.application_octect_stream)
        return handler()

    # media-type handlers

    def application_octect_stream(self):
        """
        Handler for unknown media-types. It does absolutely no
        pre-processing of the response body, so it cannot mess it up
        """
        return self.body

    def application_json(self):
        """
        Handler for application/json media-type
        """
        self.decode_body()

        try:
            pybody = json.loads(self.body, object_hook=lambda d: SimpleNamespace(**d))
        except ValueError:
            pybody = self.body

        return pybody

    text_javascript = application_json
    # XXX: This isn't technically correct, but we'll hope for the best.
    # Patches welcome!
    # Insert new media-type handlers here


class RequestBody(Body):
    """
    Encode a request body from the client, respecting the Content-Type
    field
    """
    def __init__(self, body, headers):
        self.body = body
        self.headers = headers
        self.parseContentType(self.headers.get('content-type', None))
        self.encoding = self.ctypeParameters['charset']

    def encodeBody(self):
        """
        Encode (and overwrite) self.body via the charset encoding
        specified in the request headers. This should be called by the
        media-type handler when appropriate
        """
        self.body = self.body.encode(self.encoding)

    def process(self):
        """
        Process the request body by applying a media-type specific
        handler to it.
        """
        if self.body is None:
            return None

        handlerName = self.mangled_mtype()
        handler = getattr(self, handlerName, self.application_octet_stream)
        return handler()

    # media-type handlers

    def application_octet_stream(self):
        """
        Handler for binary data and unknown media-types. Importantly,
        it does absolutely no pre-processing of the body, which means it
        will not mess it up.
        """
        return self.body

    def application_json(self):
        self.body = json.dumps(self.body)
        self.encodeBody()
        return self.body

    # Insert new Request media-type handlers here


class ConnectionProperties(object):
    __slots__ = ['api_url', 'url_prefix', 'secure_http', 'extra_headers']

    def __init__(self, **props):
        # Initialize attribute slots
        for key in self.__slots__:
            setattr(self, key, None)

        # Fill attribute slots with custom values
        for key, val in props.items():
            if key not in ConnectionProperties.__slots__:
                raise TypeError("Invalid connection property: " + str(key))
            else:
                setattr(self, key, val)

    def constructUrl(self, url):
        if self.url_prefix is None:
            return url
        return self.url_prefix + url

    def filterEmptyHeaders(self):
        if self.extra_headers is not None:
            self.extra_headers = self._filterEmptyHeaders(self.extra_headers)

    def _filterEmptyHeaders(self, headers):
        newHeaders = {}
        for header in headers.keys():
            if header is not None and header != "":
                newHeaders[header] = headers[header]

        return newHeaders

logger = logging.getLogger(__name__)

class GitHub(API):
    def __init__(self, username=None, password=None, token=None,
                 *args, **kwargs):
        extraHeaders = {'Accept': 'application/vnd.github.v3+json'}
        auth = self.generateAuthHeader(username, password, token)
        if auth is not None:
            extraHeaders['authorization'] = auth
        props = ConnectionProperties(
            api_url=kwargs.pop('api_url', 'api.github.com'),
            url_prefix=kwargs.pop('url_prefix', ''),
            secure_http=True,
            extra_headers=extraHeaders
        )

        self.setClient(GitHubClient(*args, **kwargs))
        self.setConnectionProperties(props)

    def generateAuthHeader(self, username=None, password=None, token=None):
        if token is not None:
            if password is not None:
                raise TypeError(
                    "You cannot use both password and oauth token "
                    "authenication"
                )
            return 'Token %s' % token
        elif username is not None:
            if password is None:
                raise TypeError(
                    "You need a password to authenticate as " + username
                )
            self.username = username
            return self.hash_pass(password)

    def hash_pass(self, password):
        auth_str = ('%s:%s' % (self.username, password)).encode('utf-8')
        return 'Basic '.encode('utf-8') + base64.b64encode(auth_str).strip()


class GitHubClient(Client):
    def __init__(self, username=None, password=None, token=None,
                 connection_properties=None, paginate=False,
                 sleep_on_ratelimit=True):
        super(GitHubClient, self).__init__()
        self.paginate = paginate
        self.sleep_on_ratelimit = sleep_on_ratelimit

    def request(self, method, url, bodyData, headers):
        """Low-level networking. All HTTP-method methods call this"""

        headers = self._fix_headers(headers)
        url = self.prop.constructUrl(url)

        if bodyData is None:
            # Sending a content-type w/o the body might break some
            # servers. Maybe?
            if 'content-type' in headers:
                del headers['content-type']

        # TODO: Context manager
        requestBody = RequestBody(bodyData, headers)

        if self.sleep_on_ratelimit and self.no_ratelimit_remaining():
            self.sleep_until_more_ratelimit()

        while True:
            conn = self.get_connection()
            conn.request(method, url, requestBody.process(), headers)
            response = conn.getresponse()
            status = response.status
            content = ResponseBody(response)
            self.headers = response.getheaders()

            conn.close()
            if (status == 403 and self.sleep_on_ratelimit and
                    self.no_ratelimit_remaining()):
                self.sleep_until_more_ratelimit()
            else:
                data = content.processBody()
                if self.paginate and type(data) == list:
                    data.extend(
                        self.get_additional_pages(method, bodyData, headers))
                return status, data

    def get_additional_pages(self, method, bodyData, headers):
        data = []
        url = self.get_next_link_url()
        if not url:
            return data
        logger.debug(
            'Fetching an additional paginated GitHub response page at '
            '{}'.format(url))

        status, data = self.request(method, url, bodyData, headers)
        if type(data) == list:
            data.extend(self.get_additional_pages(method, bodyData, headers))
            return data
        elif (status == 403 and self.no_ratelimit_remaining()
              and not self.sleep_on_ratelimit):
            raise TypeError(
                'While fetching paginated GitHub response pages, the GitHub '
                'ratelimit was reached but sleep_on_ratelimit is disabled. '
                'Either enable sleep_on_ratelimit or disable paginate.')
        else:
            raise TypeError(
                'While fetching a paginated GitHub response page, a non-list '
                'was returned with status {}: {}'.format(status, data))

    def no_ratelimit_remaining(self):
        headers = dict(self.headers if self.headers is not None else [])
        ratelimit_remaining = int(
            headers.get('X-RateLimit-Remaining', 1))
        return ratelimit_remaining == 0

    def ratelimit_seconds_remaining(self):
        ratelimit_reset = int(dict(self.headers).get(
            'X-RateLimit-Reset', 0))
        return max(0, int(ratelimit_reset - time.time()) + 1)

    def sleep_until_more_ratelimit(self):
        logger.debug(
            'No GitHub ratelimit remaining. Sleeping for {} seconds until {} '
            'before trying API call again.'.format(
                self.ratelimit_seconds_remaining(),
                time.strftime(
                    "%H:%M:%S", time.localtime(
                        time.time() + self.ratelimit_seconds_remaining()))
            ))
        time.sleep(self.ratelimit_seconds_remaining())

    def get_next_link_url(self):
        """Given a set of HTTP headers find the RFC 5988 Link header field,
        determine if it contains a relation type indicating a next resource and
        if so return the URL of the next resource, otherwise return an empty
        string.

        From https://github.com/requests/requests/blob/master/requests/utils.py
        """
        for value in [x[1] for x in self.headers if x[0].lower() == 'link']:
            replace_chars = ' \'"'
            value = value.strip(replace_chars)
            if not value:
                return ''
            for val in re.split(', *<', value):
                try:
                    url, params = val.split(';', 1)
                except ValueError:
                    url, params = val, ''
                link = {'url': url.strip('<> \'"')}
                for param in params.split(';'):
                    try:
                        key, value = param.split('=')
                    except ValueError:
                        break
                    link[key.strip(replace_chars)] = value.strip(replace_chars)
                if link.get('rel') == 'next':
                    return link['url']
        return ''


class Repo(object):
    def __init__(self, org, repo, token):
        self.gh = GitHub(token=token, api_url='git.autodesk.com', url_prefix='/api/v3')
        self.repo = self.gh.repos[org][repo]

    def result(func):
        def wrapper(*args, **kargs):
            status, res = func(*args, **kargs)
            if 200 <= status < 300 :
                return res
            else:
                msg = res.message if hasattr(res, 'message') else ''
                raise Exception(f"{func.__name__}: Http exception {status} {msg}")
        return wrapper

    @result
    def issues(self):
        return self.repo.issues.get()

    @lru_cache(maxsize=None, typed=False)
    @result
    def commit(self, sha):
        return self.repo.git.commits[sha].get()

    @result
    def ref(self, refname, is_tag=False):
        refname = f'tags/{refname}' if is_tag else f'heads/{refname}'
        return self.repo.git.ref[refname].get()

    def tree(self, commit_sha):
        return self.commit(commit_sha).tree.sha

    def branch_head_sha(self, branch):
        return self.ref(branch).object.sha

    @result
    def create_ref(self, name, sha):
        refname = f'refs/heads/{name}'
        body = {"ref": refname, "sha": sha}
        return self.repo.git.refs.post(body=body)

    @result
    def update_ref(self, name, sha):
        refname = f'heads/{name}'
        body = {"sha": sha, 'force': True}
        return self.repo.git.refs[refname].patch(body=body)

    @result
    def remove_ref(self,name):
        refname = f'heads/{name}'
        return self.repo.git.refs[refname].delete()


    def create_commit(self, tree, parent, msg):
        body = {'message': msg,
                'parents': [parent],
                'tree': tree}
        status, res = self.repo.git.commits.post(body=body)
        if status == 201:
            return res.sha
        raise Exception('Create commit failed')

    def merge(self, base, commit_sha, msg):
        body = {"base": base, "head": commit_sha,"commit_message": msg}
        status, res = self.repo.merges.post(body=body)
        if 200 <= status < 300:
            return res.sha, res.commit.tree.sha
        elif status == 409:
            raise Exception(f'Conflict when merging {base}')
        raise Exception(f'Merging failed when merging {base}')


def cherry_pick(commits : list, branch, repo):
    head_sha = repo.branch_head_sha(branch)
    head_commit = repo.commit(head_sha)
    head_tree = head_commit.tree.sha

    if len(commits) > 1:
        commits = sort_commits(commits, repo)
    elif len(commits[0]) != 40:
        try:
            commits = [repo.branch_head_sha(commits[0])]
        except:
            pass

    tempref = f'cherry/{randint(1000000,9999999)}'
    repo.create_ref(tempref, head_sha)
    print(f'Created a temp branch: {tempref}')
    try:
        for i, commit in enumerate(commits, start=1):
            parent = repo.commit(commit).parents[0].sha
            msg = repo.commit(commit).message
            temp = repo.create_commit(head_tree, parent, 'temp head')
            print(f'Start Cherry picking commit {i}: {msg}')
            repo.update_ref(tempref, temp)
            sha, tree = repo.merge(tempref, commit, 'merged head')
            head_sha = repo.create_commit(tree, head_sha, msg)
            head_tree = tree
            repo.update_ref(tempref, head_sha)
            print(f'Finish Cherry picking commit {i}: {msg}')
        repo.update_ref(branch, head_sha)
    finally:
        repo.remove_ref(tempref)


def rebase(branch, targetbranch, repo):
    head_commit_sha = repo.branch_head_sha(branch)
    head_target_sha = repo.branch_head_sha(targetbranch)

    tempref = f'rebase/{randint(1000000,9999999)}'
    try:
        repo.create_ref(tempref, head_commit_sha)
        sha, tree = repo.merge(tempref, head_target_sha, 'squashed merged head')
        new_head_sha = repo.create_commit(tree, head_target_sha, f'squashed merged head for {branch}')
        repo.update_ref(branch, new_head_sha)
    finally:
        repo.remove_ref(tempref)


def sort_commits(commits, repo):
    result_commit = []
    commits_copy = commits.copy()
    while True:
        for commit in commits:
            sha = repo.commit(commit).parents[0].sha
            if not sha in commits_copy:
                result_commit.append(commit)
                commits_copy.remove(commit)
        if len(commits_copy) == 0:
            break
    return  result_commit


def main(argv):
    parser = ArgumentParser()
    parser.add_argument('--repo', type=str, default='https://git.autodesk.com/AutoCAD/autocad', help='repo url')
    parser.add_argument('--action', type=str, default='cherrypick', help='cherrypick or rebase')
    parser.add_argument('--token', type=str, default=os.getenv('ACGITPWD'), help='Github token')
    parser.add_argument('--targetbranch', type=str, default=None, help='target branch name')
    parser.add_argument('commit', nargs='*', default=None, help='commits or branch')
    args = parser.parse_args(argv[1:])

    if not args.token:
        print('Github token missing!!')
        parser.print_usage()
        return 1
    if not args.commit:
        print('commits or branch missing!!')
        parser.print_usage()
        return 1
    if not args.targetbranch:
        print('target branch name missing!!')
        parser.print_usage()
        return 1

    org, repo = urlsplit(args.repo).path.split('/')[-2:]
    if args.action == 'cherrypick':
        return cherry_pick(args.commit, args.targetbranch, Repo(org, repo, token=args.token))
    else:
        return rebase(args.commit[0], args.targetbranch, Repo(org, repo, token=args.token))

if __name__ == '__main__':
    sys.exit(main(sys.argv))