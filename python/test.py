import time, os
from store import HTree, HStore 
from fnv1a import get_hash as fnv1a
import unittest
import pickle

TEST_KEY = 'test'
TEST_VER = 2
TEST_HASH = (fnv1a(TEST_KEY)* 3) & 0xffff

class TestHTree(unittest.TestCase):
    def setUp(self):
        self.htree = HTree("t.tch", 0)
        self.htree.clear()

    def tearDown(self):
        self.htree.close()
        os.unlink("t.tch")

    def testEmpty(self):
        self.assertEqual(len(self.htree), 0)
        self.assertEqual(hash(self.htree), 0)
        self.assertEqual(self.htree.list(''), '')

    def testAdd(self):
        self.htree.add(TEST_KEY, TEST_VER, 3)
        self.assertEqual(len(self.htree), 1)
        self.assertEqual(hash(self.htree), TEST_HASH)
    
    def testRemove(self):
        self.htree.remove(TEST_KEY)
        self.testEmpty()
        
        self.testAdd()
        self.htree.remove(TEST_KEY)
        self.testEmpty()

    def testSplit(self):
        self.testAdd()
        for i in range(200):
            self.htree.add('a%d'%i, i, i, 0)
        self.assertEqual(len(self.htree), 201)
        self.assertEqual(hash(self.htree), 53137)

    def testMerge(self):
        self.testSplit()

        for i in range(200):
            self.htree.remove('a%d'%i)
        self.assertEqual(len(self.htree), 1)
        self.assertEqual(hash(self.htree), TEST_HASH)

    def testList(self):
        self.testAdd()
        self.testAdd()
        l = "%s %d %d\n" % (TEST_KEY, 3, TEST_VER)
        self.assertEqual(self.htree.list(''), l)

        self.testSplit()
        self.assertEqual(len(self.htree.list('').split('\n')), 17)

    def testPerformance(self):
        st = time.time()
        for i in range(200000):
            self.htree.add('key%d'%i, i, 0, False)
        t = time.time() - st
        self.assertEqual(t<1, True)
        self.htree.flush()
        st = time.time()
        for i in range(200000):
            self.htree.add('key%d'%i, i, 0, False)
        t = time.time() - st
        self.assertEqual(t<1, True)

    def testClear(self):
        self.testSplit()
        self.htree.clear()
        self.testEmpty()

    def testSave(self):
        self.testSplit()
        path = self.htree.path
        l = len(self.htree)
        h = hash(self.htree)
        self.htree.close()

        t = HTree(path, 0)
        self.assertEqual(len(t), l)
        self.assertEqual(hash(t), h)
        t.close()

    def testRestore(self):
        self.testSplit()
        path = self.htree.path
        l = len(self.htree)
        h = hash(self.htree)
        self.htree.close()

        import pytc
        db = pytc.HDB()
        db.open(path, pytc.HDBOREADER|pytc.HDBOWRITER)
        try:
            db.out("__pool__")
        except:
            pass
        db.close()
        
        t = HTree(path, 0)
        self.assertEqual(len(t), l)
        self.assertEqual(hash(t), h)
        t.close()
        
        import pytc
        db = pytc.HDB()
        db.open(path, pytc.HDBOREADER|pytc.HDBOWRITER)
        #assert db["__sync__"] == "1"
        try:
            db.out("__sync__")
        except:
            pass
        db.close()
        
        t = HTree(path, 0)
        self.assertEqual(len(t), l)
        self.assertEqual(hash(t), h)
        t.close()

    def testGetHash(self):
        self.testSplit()
        h, c = self.htree.get_hash("@")
        assert h == hash(self.htree)
        assert c == len(self.htree)

        h, ver = self.htree.get_hash(TEST_KEY)
        assert h == 3
        assert ver == TEST_VER

    def testDepth(self):
        self.testSplit()
        h, c = self.htree.get_hash("@1")
        s = self.htree.list("1")

        t = HTree("tt.tch", 1)
        for key, ver, ha in [l.split(' ') for l in s.split("\n") if l]:
            t.add(key, int(ver), int(ha))
        self.assertEqual(len(t), c)
        self.assertEqual(hash(t), h)
        self.assertEqual(t.list(''), s)
        t.close()
        os.unlink('tt.tch')


class TestHStore(unittest.TestCase):
    height = 0
    def setUp(self):
        self.store = HStore("/tmp/tmpdb2", self.height)
        self.store.clear()

    def tearDown(self):
        self.store.clear()
        self.store.close()

    def testSetGet(self):
        self.assertEqual(self.store.get('test'), None)
        self.store.set('test', 'value')
        self.assertEqual(self.store.get('test'), 'value')
        self.store.delete('test')
        self.assertEqual(self.store.get('test'), None)

    def testVersion(self):
        self.store.delete('test')
        self.assertEqual(self.store.get('test'), None)

        self.store.set('test', 'value1', 0)
        self.assertEqual(self.store.get('test'), 'value1')
        #self.assertEqual(self.store.get('@'), 'test 1984411239 1\n')

        self.store.set('test', 'value2', 0)
        self.assertEqual(self.store.get('test'), 'value2')

        self.store.set('test', 'value3', 2)
        self.assertEqual(self.store.get('test'), 'value2')

        self.store.set('test', 'value4', 4)
        self.assertEqual(self.store.get('test'), 'value4')

        self.store.delete('test')
        self.assertEqual(self.store.get('test'), None)

    def testHash(self):
        for i in range(200):
            self.store.set('/test/test%d.jpg'%i, 'value%d'%i)
        s = self.store.get('@')
        n = sum(int(l.split(' ')[2]) for l in s.split('\n') if l)
        self.assertEqual(n, 200)
        s = self.store.get('@0')
        n = sum(1 for l in s.split('\n') if l)
        if n == 16:
            n = sum(int(l.split(' ')[2]) for l in s.split('\n') if l)
        self.assertEqual(n, 10)

    def testScan(self):
        self.testHash()
        self.store.close()
        
        os.unlink(self.store.path + '/.0.index')
        t = HStore(self.store.path, self.store.height)
        t.check()
        try:
            s = t.get('@')
            n = sum(int(l.split(' ')[2]) for l in s.split('\n') if l)
            self.assertEqual(n, 200)
            s = t.get('@0')
            n = sum(1 for l in s.split('\n') if l)
            if n == 16:
                n = sum(int(l.split(' ')[2]) for l in s.split('\n') if l)
            self.assertEqual(n, 10)
        finally:
            t.close()

    def testRange(self):
        self.store.close()
        t = HStore(self.store.path, 1, 0, 8)
        for i in range(200):
            t.set('/test/test%d.jpg'%i, 'value%d'%i)
        s = t.get('@')
        n = sum(int(l.split(' ')[2]) for l in s.split('\n') if l)
        t.close()
        self.assertEqual(n, 110)

class TestHStore1(TestHStore):
    def testFlag(self):
        self.store.set("test_flag", "value", 2, 17)
        v = self.store.get("?test_flag")
        ver, hash, flag, modified = v.split(' ')
        self.assertEqual(int(ver), 2)
        self.assertEqual(int(flag), 17)
        vh = fnv1a("value") + len("value") * 97
        self.assertEqual(int(hash), vh);

class TestHStore2(TestHStore):
    height = 1

class TestHStore3(TestHStore):
    height = 2
