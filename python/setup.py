from setuptools import setup, Extension
from Cython.Distutils import build_ext

setup(
    name="beansdb",
    cmdclass={'build_ext': build_ext},
    ext_modules=[
        Extension("store", ["store.pyx", "../htree.c", "../hstore.c"],
                libraries=["tokyocabinet"],
    )],
    packages=["beansdb"],
    test_suite="test",
    install_requires=['cython'],
    zip_safe=False,
    version="0.3.0",
)
