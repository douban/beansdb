from setuptools import setup, Extension
from Cython.Distutils import build_ext

setup(
    cmdclass = {'build_ext': build_ext},
    ext_modules = [
        Extension("store", ["store.pyx", "../htree.c", "../hstore.c"],
                libraries=["tokyocabinet"],
    )],
    test_suite="test",
)
