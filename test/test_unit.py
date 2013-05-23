import httplib
import os
import shutil
import signal
import sys
import tempfile
import time
import unittest

srv_pid = 0
base_dir = None

def poke_server(netloc):

    conn = httplib.HTTPConnection(netloc)
    conn.request('GET', '/', '', {'X-Timestamp': '1'})
    resp = conn.getresponse()
    body = resp.read()
    # url = resp.getheader('x-storage-url')
    return resp.status

class TestUnit(unittest.TestCase):

    def setUp(self):
        global base_dir
        base_dir = tempfile.mkdtemp()

        # if only we could create members of TestUnit...
        global srv_pid

        srv_path = "./oserver"
        cfg_path = os.path.join(base_dir, "oserver.conf")
        port_path = os.path.join(base_dir, "oserver.port")

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
        shutil.rmtree(base_dir)

    def test_root(self):
        status = poke_server(srv_netloc)
        self.assertEquals(status, 200)
