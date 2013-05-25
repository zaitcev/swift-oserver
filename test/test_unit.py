from __future__ import with_statement
import errno
import httplib
import os
#import cPickle as pickle
import pickle
import shutil
import signal
import sys
import tempfile
import time
import traceback
import unittest
import xattr

from hashlib import md5
from tempfile import mkstemp
from contextlib import contextmanager


DATADIR = 'objects'
PICKLE_PROTOCOL = 2
METADATA_KEY = 'user.swift.metadata'
MAX_OBJECT_NAME_LENGTH = 1024
HASH_FILE = 'hashes.pkl'
# keep these lower-case
DISALLOWED_HEADERS = set('content-length content-type deleted etag'.split())


HASH_PATH_SUFFIX = '583abcbde3ff4258'
HASH_PATH_PREFIX = ''


srv_pid = 0
base_dir = None


def read_metadata(fd):
    """
    Helper function to read the pickled metadata from an object file.

    :param fd: file descriptor to load the metadata from

    :returns: dictionary of metadata
    """
    metadata = ''
    key = 0
    try:
        while True:
            metadata += xattr.getxattr(fd, '%s%s' % (METADATA_KEY, (key or '')))
            key += 1
    except IOError:
        pass
    return pickle.loads(metadata)

def write_metadata(fd, metadata):
    """
    Helper function to write pickled metadata for an object file.

    :param fd: file descriptor to write the metadata
    :param metadata: metadata to write
    """
    metastr = pickle.dumps(metadata, PICKLE_PROTOCOL)
    key = 0
    while metastr:
        xattr.setxattr(fd, '%s%s' % (METADATA_KEY, key or ''), metastr[:254])
        metastr = metastr[254:]
        key += 1

def normalize_timestamp(timestamp):
    """
    Format a timestamp (string or numeric) into a standardized
    xxxxxxxxxx.xxxxx format.

    :param timestamp: unix timestamp
    :returns: normalized timestamp as a string
    """
    return "%016.05f" % (float(timestamp))

def mkdirs(path):
    """
    Ensures the path is a directory or makes it if not. Errors if the path
    exists but is a file or on permissions failure.

    :param path: path to create
    """
    if not os.path.isdir(path):
        try:
            os.makedirs(path)
        except OSError, err:
            if err.errno != errno.EEXIST or not os.path.isdir(path):
                raise

def renamer(old, new):
    """
    Attempt to fix / hide race conditions like empty object directories
    being removed by backend processes during uploads, by retrying.

    :param old: old path to be renamed
    :param new: new path to be renamed to
    """
    try:
        mkdirs(os.path.dirname(new))
        os.rename(old, new)
    except OSError:
        mkdirs(os.path.dirname(new))
        os.rename(old, new)

def storage_directory(datadir, partition, hash):
    """
    Get the storage directory

    :param datadir: Base data directory
    :param partition: Partition
    :param hash: Account, container or object hash
    :returns: Storage directory
    """
    return os.path.join(datadir, str(partition), hash[-3:], hash)

def hash_path(account, container=None, object=None, raw_digest=False):
    """
    Get the connonical hash for an account/container/object

    :param account: Account
    :param container: Container
    :param object: Object
    :param raw_digest: If True, return the raw version rather than a hex digest
    :returns: hash string
    """
    if object and not container:
        raise ValueError('container is required if object is provided')
    paths = [account]
    if container:
        paths.append(container)
    if object:
        paths.append(object)
    if raw_digest:
        return md5(HASH_PATH_PREFIX + '/' + '/'.join(paths)
                   + HASH_PATH_SUFFIX).digest()
    else:
        return md5(HASH_PATH_PREFIX + '/' + '/'.join(paths)
                   + HASH_PATH_SUFFIX).hexdigest()

@contextmanager
def lock_path(directory, timeout=10):
    """
    Context manager that acquires a lock on a directory.  This will block until
    the lock can be acquired, or the timeout time has expired (whichever occurs
    first).

    For locking exclusively, file or directory has to be opened in Write mode.
    Python doesn't allow directories to be opened in Write Mode. So we
    workaround by locking a hidden file in the directory.

    :param directory: directory to be locked
    :param timeout: timeout (in seconds)
    """
    mkdirs(directory)
    lockpath = '%s/.lock' % directory
    fd = os.open(lockpath, os.O_WRONLY | os.O_CREAT)
    try:
        #with LockTimeout(timeout, lockpath):
        #    while True:
        #        try:
        #            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        #            break
        #        except IOError, err:
        #            if err.errno != errno.EAGAIN:
        #                raise
        #        sleep(0.01)
        yield True
    finally:
        os.close(fd)

def write_pickle(obj, dest, tmp=None, pickle_protocol=0):
    """
    Ensure that a pickle file gets written to disk.  The file
    is first written to a tmp location, ensure it is synced to disk, then
    perform a move to its final location

    :param obj: python object to be pickled
    :param dest: path of final destination file
    :param tmp: path to tmp to use, defaults to None
    :param pickle_protocol: protocol to pickle the obj with, defaults to 0
    """
    if tmp is None:
        tmp = os.path.dirname(dest)
    fd, tmppath = mkstemp(dir=tmp, suffix='.tmp')
    with os.fdopen(fd, 'wb') as fo:
        pickle.dump(obj, fo, pickle_protocol)
        fo.flush()
        os.fsync(fd)
        renamer(tmppath, dest)

#class MessageTimeout(Timeout):
#
#    def __init__(self, seconds=None, msg=None):
#        Timeout.__init__(self, seconds=seconds)
#        self.msg = msg
#
#    def __str__(self):
#        return '%s: %s' % (Timeout.__str__(self), self.msg)

class SwiftException(Exception):
    pass

class DiskFileCollision(SwiftException):
    pass

#class LockTimeout(MessageTimeout):
#    pass

def quarantine_renamer(device_path, corrupted_file_path):
    """
    In the case that a file is corrupted, move it to a quarantined
    area to allow replication to fix it.

    :params device_path: The path to the device the corrupted file is on.
    :params corrupted_file_path: The path to the file you want quarantined.

    :returns: path (str) of directory the file was moved to
    :raises OSError: re-raises non errno.EEXIST / errno.ENOTEMPTY
                     exceptions from rename
    """
    from_dir = os.path.dirname(corrupted_file_path)
    to_dir = os.path.join(device_path, 'quarantined', 'objects',
                          os.path.basename(from_dir))
    invalidate_hash(os.path.dirname(from_dir))
    try:
        renamer(from_dir, to_dir)
    except OSError, e:
        if e.errno not in (errno.EEXIST, errno.ENOTEMPTY):
            raise
        to_dir = "%s-%s" % (to_dir, uuid.uuid4().hex)
        renamer(from_dir, to_dir)
    return to_dir

def invalidate_hash(suffix_dir):
    """
    Invalidates the hash for a suffix_dir in the partition's hashes file.

    :param suffix_dir: absolute path to suffix dir whose hash needs
                       invalidating
    """

    suffix = os.path.basename(suffix_dir)
    partition_dir = os.path.dirname(suffix_dir)
    hashes_file = os.path.join(partition_dir, HASH_FILE)
    with lock_path(partition_dir):
        try:
            with open(hashes_file, 'rb') as fp:
                hashes = pickle.load(fp)
            if suffix in hashes and not hashes[suffix]:
                return
        except Exception:
            return
        hashes[suffix] = None
        write_pickle(hashes, hashes_file, partition_dir, PICKLE_PROTOCOL)

class DiskFile(object):
    """
    Manage object files on disk.

    :param path: path to devices on the node
    :param device: device name
    :param partition: partition on the device the object lives in
    :param account: account name for the object
    :param container: container name for the object
    :param obj: object name for the object
    :param keep_data_fp: if True, don't close the fp, otherwise close it
    :param disk_chunk_size: size of chunks on file reads
    :param iter_hook: called when __iter__ returns a chunk
    :raises DiskFileCollision: on md5 collision
    """

    def __init__(self, path, device, partition, account, container, obj,
                 keep_data_fp=False, disk_chunk_size=65536,
                 iter_hook=None):
        self.disk_chunk_size = disk_chunk_size
        self.iter_hook = iter_hook
        self.name = '/' + '/'.join((account, container, obj))
        name_hash = hash_path(account, container, obj)
        self.datadir = os.path.join(
            path, device, storage_directory(DATADIR, partition, name_hash))
        self.device_path = os.path.join(path, device)
        self.tmpdir = os.path.join(path, device, 'tmp')
        self.tmppath = None
        self.metadata = {}
        self.meta_file = None
        self.data_file = None
        self.fp = None
        self.iter_etag = None
        self.started_at_0 = False
        self.read_to_eof = False
        self.quarantined_dir = None
        self.keep_cache = False
        self.suppress_file_closing = False
        if not os.path.exists(self.datadir):
            return
        files = sorted(os.listdir(self.datadir), reverse=True)
        for file in files:
            if file.endswith('.ts'):
                self.data_file = self.meta_file = None
                self.metadata = {'deleted': True}
                return
            if file.endswith('.meta') and not self.meta_file:
                self.meta_file = os.path.join(self.datadir, file)
            if file.endswith('.data') and not self.data_file:
                self.data_file = os.path.join(self.datadir, file)
                break
        if not self.data_file:
            return
        self.fp = open(self.data_file, 'rb')
        self.metadata = read_metadata(self.fp)
        if not keep_data_fp:
            self.close(verify_file=False)
        if self.meta_file:
            with open(self.meta_file) as mfp:
                for key in self.metadata.keys():
                    if key.lower() not in DISALLOWED_HEADERS:
                        del self.metadata[key]
                self.metadata.update(read_metadata(mfp))
        if 'name' in self.metadata:
            if self.metadata['name'] != self.name:
                raise DiskFileCollision('Client path does not match path '
                                        'stored in object metadata')

    def __iter__(self):
        """Returns an iterator over the data file."""
        try:
            #dropped_cache = 0
            read = 0
            self.started_at_0 = False
            self.read_to_eof = False
            if self.fp.tell() == 0:
                self.started_at_0 = True
                self.iter_etag = md5()
            while True:
                chunk = self.fp.read(self.disk_chunk_size)
                if chunk:
                    if self.iter_etag:
                        self.iter_etag.update(chunk)
                    read += len(chunk)
                    #if read - dropped_cache > (1024 * 1024):
                    #    self.drop_cache(self.fp.fileno(), dropped_cache,
                    #                    read - dropped_cache)
                    #    dropped_cache = read
                    yield chunk
                    if self.iter_hook:
                        self.iter_hook()
                else:
                    self.read_to_eof = True
                    #self.drop_cache(self.fp.fileno(), dropped_cache,
                    #                read - dropped_cache)
                    break
        finally:
            if not self.suppress_file_closing:
                self.close()

    def app_iter_range(self, start, stop):
        """Returns an iterator over the data file for range (start, stop)"""
        if start or start == 0:
            self.fp.seek(start)
        if stop is not None:
            length = stop - start
        else:
            length = None
        for chunk in self:
            if length is not None:
                length -= len(chunk)
                if length < 0:
                    # Chop off the extra:
                    yield chunk[:length]
                    break
            yield chunk

    def app_iter_ranges(self, ranges, content_type, boundary, size):
        """Returns an iterator over the data file for a set of ranges"""
        if not ranges:
            yield ''
        else:
            try:
                self.suppress_file_closing = True
                for chunk in multi_range_iterator(
                        ranges, content_type, boundary, size,
                        self.app_iter_range):
                    yield chunk
            finally:
                self.suppress_file_closing = False
                self.close()

    def _handle_close_quarantine(self):
        """Check if file needs to be quarantined"""
        try:
            self.get_data_file_size()
        except DiskFileError:
            self.quarantine()
            return
        except DiskFileNotExist:
            return

        if self.iter_etag and self.started_at_0 and self.read_to_eof and \
                'ETag' in self.metadata and \
                self.iter_etag.hexdigest() != self.metadata.get('ETag'):
            self.quarantine()

    def close(self, verify_file=True):
        """
        Close the file. Will handle quarantining file if necessary.

        :param verify_file: Defaults to True. If false, will not check
                            file to see if it needs quarantining.
        """
        if self.fp:
            try:
                if verify_file:
                    self._handle_close_quarantine()
            except (Exception), e:
                print >>sys.stderr, \
                    'ERROR DiskFile %(data_file)s in ' \
                    '%(data_dir)s close failure: %(exc)s : %(stack)' % \
                    {'exc': e, 'stack': ''.join(traceback.format_stack()),
                     'data_file': self.data_file, 'data_dir': self.datadir}
            finally:
                self.fp.close()
                self.fp = None

    def is_deleted(self):
        """
        Check if the file is deleted.

        :returns: True if the file doesn't exist or has been flagged as
                  deleted.
        """
        return not self.data_file or 'deleted' in self.metadata

    def is_expired(self):
        """
        Check if the file is expired.

        :returns: True if the file has an X-Delete-At in the past
        """
        return ('X-Delete-At' in self.metadata and
                int(self.metadata['X-Delete-At']) <= time.time())

    @contextmanager
    def mkstemp(self):
        """
        Contextmanager to make a temporary file.
        """
        if not os.path.exists(self.tmpdir):
            mkdirs(self.tmpdir)
        fd, self.tmppath = mkstemp(dir=self.tmpdir)
        try:
            yield fd
        finally:
            try:
                os.close(fd)
            except OSError:
                pass
            tmppath, self.tmppath = self.tmppath, None
            try:
                os.unlink(tmppath)
            except OSError:
                pass

    def put(self, fd, fsize, metadata, extension='.data'):
        """
        Finalize writing the file on disk, and renames it from the temp file to
        the real location.  This should be called after the data has been
        written to the temp file.

        :param fd: file descriptor of the temp file
        :param fsize: final on-disk size of the created file
        :param metadata: dictionary of metadata to be written
        :param extension: extension to be used when making the file
        """
        assert self.tmppath is not None
        metadata['name'] = self.name
        timestamp = normalize_timestamp(metadata['X-Timestamp'])
        # Write the metadata before calling fsync() so that both data and
        # metadata are flushed to disk.
        write_metadata(fd, metadata)
        ## We call fsync() before calling drop_cache() to lower the amount of
        ## redundant work the drop cache code will perform on the pages (now
        ## that after fsync the pages will be all clean).
        #tpool.execute(fsync, fd)
        ## From the Department of the Redundancy Department, make sure we
        ## call drop_cache() after fsync() to avoid redundant work (pages
        ## all clean).
        #self.drop_cache(fd, 0, fsize)
        invalidate_hash(os.path.dirname(self.datadir))
        # After the rename completes, this object will be available for other
        # requests to reference.
        renamer(self.tmppath,
                os.path.join(self.datadir, timestamp + extension))
        self.metadata = metadata

    def put_metadata(self, metadata, tombstone=False):
        """
        Short hand for putting metadata to .meta and .ts files.

        :param metadata: dictionary of metadata to be written
        :param tombstone: whether or not we are writing a tombstone
        """
        extension = '.ts' if tombstone else '.meta'
        with self.mkstemp() as fd:
            self.put(fd, 0, metadata, extension=extension)

    def unlinkold(self, timestamp):
        """
        Remove any older versions of the object file.  Any file that has an
        older timestamp than timestamp will be deleted.

        :param timestamp: timestamp to compare with each file
        """
        timestamp = normalize_timestamp(timestamp)
        for fname in os.listdir(self.datadir):
            if fname < timestamp:
                try:
                    os.unlink(os.path.join(self.datadir, fname))
                except OSError, err:    # pragma: no cover
                    if err.errno != errno.ENOENT:
                        raise

    #def drop_cache(self, fd, offset, length):
    #    """Method for no-oping buffer cache drop method."""
    #    if not self.keep_cache:
    #        drop_buffer_cache(fd, offset, length)

    # XXX later
    def quarantine(self):
        """
        In the case that a file is corrupted, move it to a quarantined
        area to allow replication to fix it.

        :returns: if quarantine is successful, path to quarantined
                  directory otherwise None
        """
        if not (self.is_deleted() or self.quarantined_dir):
            self.quarantined_dir = quarantine_renamer(self.device_path,
                                                      self.data_file)
            return self.quarantined_dir

    def get_data_file_size(self):
        """
        Returns the os.path.getsize for the file.  Raises an exception if this
        file does not match the Content-Length stored in the metadata. Or if
        self.data_file does not exist.

        :returns: file size as an int
        :raises DiskFileError: on file size mismatch.
        :raises DiskFileNotExist: on file not existing (including deleted)
        """
        try:
            file_size = 0
            if self.data_file:
                file_size = os.path.getsize(self.data_file)
                if 'Content-Length' in self.metadata:
                    metadata_size = int(self.metadata['Content-Length'])
                    if file_size != metadata_size:
                        raise DiskFileError(
                            'Content-Length of %s does not match file size '
                            'of %s' % (metadata_size, file_size))
                return file_size
        except OSError, err:
            if err.errno != errno.ENOENT:
                raise
        raise DiskFileNotExist('Data File does not exist.')


class TestUnit(unittest.TestCase):

    # XXX This is executed for every test. Relocate somewhere like setup().
    def setUp(self):
        global base_dir
        #base_dir = tempfile.mkdtemp(dir=os.getcwd())
        base_dir = tempfile.mkdtemp(dir=".")

        # if only we could create members of TestUnit...
        global srv_pid

        srv_path = "./oserver"
        cfg_path = os.path.join(base_dir, "oserver.conf")
        port_path = os.path.join(base_dir, "oserver.port")

        node_dir = os.path.join(base_dir, "srv.node")
        os.mkdir(node_dir)

        fp = open(cfg_path, "w")
        fp.write("[DEFAULT]\n")
        fp.write("bind_port=auto\n")
        fp.write("port_file=%s\n" % port_path)
        fp.close()

        # Replace with os.spawnv(os.P_NOWAIT, srv_path, args) for Windows
        srv_pid = os.fork()
        if srv_pid == 0:
            os.execv(srv_path, ["oserver", "-C", cfg_path, "-E" ])
            print >>sys.stderr, "exec failed"
            os._exit(1)

        time.sleep(3)

        fp = open(port_path, 'r')
        global srv_netloc
        srv_netloc = fp.readline().rstrip('\n')
        fp.close()

        os.kill(srv_pid, 0)

    def tearDown(self):
        os.kill(srv_pid, signal.SIGTERM)
        # shutil.rmtree(base_dir)

    def test_root(self):
        status = poke_server(srv_netloc)
        # XXX Real object-server returns 400 Bad Request on root path
        self.assertEquals(status, 200)

    def test_head_one(self):
        obj_path = create_object(base_dir)

def poke_server(netloc):
    conn = httplib.HTTPConnection(netloc)
    conn.request('GET', '/', '', {'X-Timestamp': '1'})
    resp = conn.getresponse()
    body = resp.read()
    # url = resp.getheader('x-storage-url')
    return resp.status

#    device, partition, account, container, obj = \
#        split_path(unquote(request.path), 5, 5, True)

def create_object(top_dir):
    node_dir = os.path.join(top_dir, "srv.node")

    data_str = "moo"
    data_size = len(data_str)
    etag_b = md5()
    etag_b.update(data_str)
    data_etag = etag_b.hexdigest()

    device = 'd2'
    partition = '92714'
    account = 'AUTH_test'
    container = 'testcont'
    obj = 'x.diff'

    disk_file = DiskFile(node_dir, device, partition, account, container, obj)
    with disk_file.mkstemp() as fd:
        written = os.write(fd, data_str)
        metadata = {
            'X-Timestamp': normalize_timestamp(time.time()),
            'Content-Type': 'application/octet-stream',
            'ETag': data_etag,
            'Content-Length': str(data_size),
        }
        disk_file.put(fd, data_size, metadata)

    return None
