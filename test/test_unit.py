import httplib
import os
# import shutil
import signal
import sys
# import tempfile
import time
import unittest

srv_pid = 0
#base_dir = None

def poke_server():
    conn = httplib.HTTPConnection("localhost:6000")
    conn.request('GET', '/', '', {'X-Timestamp': '1'})
    resp = conn.getresponse()
    body = resp.read()
    # url = resp.getheader('x-storage-url')
    if resp.status != 200:
        print "Bad status", resp.status
    else:
        print "OK status"

class TestUnit(unittest.TestCase):

    def setUp(self):
        #global base_dir
        #base_dir = tempfile.mkdtemp()

        # if only we could create members of TestUnit...
        global srv_pid

        srv_path = "./oserver"

        # Replace with os.spawnv(os.P_NOWAIT, srv_path, args) for Windows
        srv_pid = os.fork()
        if srv_pid == 0:
            os.execv(srv_path, ["oserver", ])
            print >>sys.stderr, "exec failed"
            os._exit(1)

        time.sleep(3)
        os.kill(srv_pid, 0)

    def tearDown(self):
        os.kill(srv_pid, signal.SIGTERM)
        # XXX P3
        # shutil.rmtree(base_dir)

    def test_root(self):
        poke_server()
        self.assertEquals(export_str, export_master)
