"""
Setup script for the SKALE Threshold Encryption Python package.
"""
import os
import shutil
from setuptools import setup, find_packages
from setuptools.command.build_py import build_py

# Configuration
PACKAGE_NAME = 'skale_te'
LIB_NAME = 'libencrypt.so'
BUILD_TARGET_NAME = 'libskale_te_python.so'

class CustomBuildPy(build_py):
    """
    Custom build command to copy the shared library into the package directory.
    """
    def run(self):
        current_dir = os.path.dirname(os.path.abspath(__file__))
        possible_build_dirs = [
            os.path.join(current_dir, '../../build'),
            os.path.join(current_dir, '../../build/lib'),
            os.path.join(current_dir, '../build'),
        ]

        found_lib = None
        for build_dir in possible_build_dirs:
            p = os.path.join(build_dir, BUILD_TARGET_NAME)
            if os.path.exists(p):
                found_lib = p
                break

        if found_lib is None:
            raise FileNotFoundError(
                f"Could not find {BUILD_TARGET_NAME} in "
                f"{', '.join(possible_build_dirs)}. "
                "Please build the C++ library first."
            )

        target_path = os.path.join(current_dir, PACKAGE_NAME, LIB_NAME)

        shutil.copy2(found_lib, target_path)
        os.chmod(target_path, 0o755)

        super().run()

setup(
    name='skale-te',
    version=os.environ.get('PACKAGE_VERSION', '0.0.1'),
    description='Python bindings for SKALE Threshold Encryption',
    author='SKALE Network',
    packages=find_packages(),
    include_package_data=True,
    package_data={
        'skale_te': ['*.so'],
    },
    cmdclass={
        'build_py': CustomBuildPy,
    },
    classifiers=[
        'Programming Language :: Python :: 3',
        'Operating System :: POSIX :: Linux',
    ],
    python_requires='>=3.6',
)
