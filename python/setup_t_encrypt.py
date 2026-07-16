"""
Setup script for the SKALE Threshold Encryption Python package.
"""
import os
import shutil
from setuptools import setup, find_packages
from setuptools.command.build_py import build_py
from setuptools.dist import Distribution

# Configuration
PACKAGE_NAME = 't_encrypt'
LIB_NAME = 'libencrypt.so'
BUILD_TARGET_NAME = 'libt_encrypt_python.so'


def resolve_built_library_path() -> str:
    override_path = os.environ.get('T_ENCRYPT_LIB_PATH')
    if override_path:
        if not os.path.exists(override_path):
            raise FileNotFoundError(
                f"T_ENCRYPT_LIB_PATH points to missing file: {override_path}"
            )
        return override_path
    else:
        raise RuntimeError(
            "Environment variable T_ENCRYPT_LIB_PATH is not set. ")

class CustomBuildPy(build_py):
    """
    Custom build command to copy the shared library into the package directory.
    """
    def run(self):
        current_dir = os.path.dirname(os.path.abspath(__file__))
        found_lib = resolve_built_library_path()

        target_path = os.path.join(current_dir, PACKAGE_NAME, LIB_NAME)

        shutil.copy2(found_lib, target_path)
        os.chmod(target_path, 0o755)

        super().run()


class BinaryDistribution(Distribution):
    def has_ext_modules(self):
        return True

setup(
    name='t-encrypt',
    version='0.0.2',
    description='Python bindings for SKALE Threshold Encryption',
    author='SKALE Network',
    packages=find_packages(),
    include_package_data=True,
    package_data={
        't_encrypt': ['*.so'],
    },
    cmdclass={
        'build_py': CustomBuildPy,
    },
    distclass=BinaryDistribution,
    classifiers=[
        'Programming Language :: Python :: 3',
        'Operating System :: POSIX :: Linux',
    ],
    python_requires='>=3.11',
)
