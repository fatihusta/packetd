"""Tests packetd playback functionality"""
# pylint: disable=no-self-use
import subprocess
import unittest
import time
import os
import tests.test_registry as test_registry

def packetd_traffic_bypass():
    """Tells packetd to bypass real traffic"""
    subprocess.call("curl -X POST -s -o - -H 'Content-Type: application/json; charset=utf-8' -d '{\"bypass\":\"TRUE\"}' 'http://localhost/api/control/traffic' >> /tmp/subproc.out", shell=True)

def packetd_traffic_resume():
    """Tells packetd to resume real traffic"""
    subprocess.call("curl -X POST -s -o - -H 'Content-Type: application/json; charset=utf-8' -d '{\"bypass\":\"FALSE\"}' 'http://localhost/api/control/traffic' >> /tmp/subproc.", shell=True)

def download_playback_file():
    """download the playback file"""
    result = subprocess.call("rm -f /tmp/playtest.cap", shell=True)
    result = subprocess.call("wget -q -P /tmp http://test.untangle.com/packetd/playtest.cap", shell=True)
    return result

def playback_start(filename, speedup_multiplier=1):
    """start the playback file"""
    result = subprocess.call("curl -X POST -s -o - -H 'Content-Type: application/json; charset=utf-8' -d '{\"filename\":\"%s\",\"speed\":\"%i\"}' 'http://localhost/api/warehouse/playback' >> /tmp/subproc.out" % (filename, speedup_multiplier*100), shell=True)
    return result

def playback_cleanup():
    """start the playback file"""
    result = subprocess.call("curl -X POST -s -o - -H 'Content-Type: application/json; charset=utf-8' -d '{}' 'http://localhost/api/warehouse/cleanup' >> /tmp/subproc.out", shell=True)
    return result

def playback_wait():
    """wait on a playback to finish, returns 0 on success, 1 if timeout before 30 seconds"""
    counter = 0
    busy = 1
    while busy != 0 and counter < 30:
        counter += 1
        time.sleep(1)
        check = subprocess.Popen(["curl", "http://localhost/api/warehouse/status"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        result = str(check.communicate()[0])
        if "IDLE" in result:
            return 0
    return 1

def read_dict():
    """return the whole dict as a string"""
    dictfile = open("/proc/net/dict/all", "r")
    rawdata = dictfile.read()
    dictfile.close()
    return rawdata

def read_dict_session(ctid):
    """return the dict for a specific session"""
    dictfile = open("/proc/net/dict/read", "r+")
    dictfile.write("table=session,key_int=" + ctid + ",")
    rawdata = dictfile.read()
    dictfile.close()
    return rawdata

def get_file_md5(filename):
    """return the md5sum for the specified file"""
    if os.path.isfile(filename):
        check = subprocess.Popen(["md5sum", "/tmp/playtest.cap"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = check.communicate()[0]
        return output.split()[0]
    else:
        return "0"

def clear_dict():
    """Clears the dictionary of the fack session IDs in the playbacks"""
    dictfile = open("/proc/net/dict/delete", "r+")
    dictfile.write("table=session,key_int=" + PlaybackTests.http_ctid + ",")
    dictfile.close()

    dictfile = open("/proc/net/dict/delete", "r+")
    dictfile.write("table=session,key_int=" + PlaybackTests.https_ctid + ",")
    dictfile.close()


class PlaybackTests(unittest.TestCase):
    "Tests the playback functionality"

    file_hash = "f8388c823679da7db0a4cb7856bf717c".encode('UTF-8')
    https_ctid = "4073347072"   # session traffic for wget https://www.japan.go.jp
    http_ctid = "4073346816"    # session traffic for wget http://www.neverssl.com
    speedup_multiplier = 100
    
    @staticmethod
    def moduleName():
        """moduleName unittest method"""
        return "playback"

    def initialSetUp(self):
        """initialSetup unittest method"""
        packetd_traffic_bypass()

    def setUp(self):
        """setUp unittest method"""
        print()
        clear_dict()

    def test_010_check_empty_table(self):
        '''verify the ctids aren't in the dictionary'''
        rawdata = read_dict()
        assert "table: session key_int: " + PlaybackTests.http_ctid not in rawdata
        assert "table: session key_int: " + PlaybackTests.https_ctid not in rawdata

    def test_020_check_capture_file(self):
        '''download the playback file needed for our tests'''
        md5sum = get_file_md5("/tmp/playtest.cap")
        print(md5sum)
        if md5sum != self.file_hash:
            assert download_playback_file() == 0
        md5sum = get_file_md5("/tmp/playtest.cap")
        print(md5sum)
        print(self.file_hash)
        assert md5sum == self.file_hash

    def test_030_playback_capture_file(self):
        '''playback the capture file and wait for it to finish'''
        assert playback_start("/tmp/playtest.cap") == 0
        assert playback_wait() == 0
        rawdata = read_dict_session(PlaybackTests.http_ctid)
        playback_cleanup()
        assert rawdata != ""

    def test_031_playback_capture_file_speedup(self):
        '''playback the capture file and wait for it to finish'''
        assert playback_start("/tmp/playtest.cap", self.speedup_multiplier) == 0
        assert playback_wait() == 0
        rawdata = read_dict_session(PlaybackTests.http_ctid)
        playback_cleanup()
        assert rawdata != ""

    def test_040_check_http_classify(self):
        '''check classify HTTP session details in the dictionary'''
        assert playback_start("/tmp/playtest.cap", self.speedup_multiplier) == 0
        assert playback_wait() == 0
        rawdata = read_dict_session(PlaybackTests.http_ctid)
        playback_cleanup()
        print(rawdata)
        assert "field: application_name string: HTTP" in rawdata
        assert "field: application_protochain string: /IP/TCP/HTTP" in rawdata

    def test_041_check_https_geoip(self):
        '''check HTTPS session geoip details in the dictionary'''
        assert playback_start("/tmp/playtest.cap", self.speedup_multiplier) == 0
        assert playback_wait() == 0
        rawdata = read_dict_session(PlaybackTests.https_ctid)
        playback_cleanup()
        assert "field: server_country string: JP" in rawdata

    def test_042_check_https_sni(self):
        '''check HTTPS session sni details in the dictionary'''
        assert playback_start("/tmp/playtest.cap", self.speedup_multiplier) == 0
        assert playback_wait() == 0
        rawdata = read_dict_session(PlaybackTests.https_ctid)
        playback_cleanup()
        assert "field: ssl_sni string: www.japan.go.jp" in rawdata

    def test_043_check_https_cert(self):
        '''check HTTPS session cert details in the dictionary'''
        assert playback_start("/tmp/playtest.cap", self.speedup_multiplier) == 0
        assert playback_wait() == 0
        rawdata = read_dict_session(PlaybackTests.https_ctid)
        playback_cleanup()
        assert "field: certificate_subject_cn string: www.japan.go.jp" in rawdata

    def finalTearDown(self):
        playback_cleanup()
        packetd_traffic_resume()

test_registry.register_module("playback", PlaybackTests)