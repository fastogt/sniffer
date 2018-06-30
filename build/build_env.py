#!/usr/bin/env python3
import os
import shutil
import sys

from pyfastogt import run_command
from pyfastogt import system_info
from pyfastogt import utils

OPENSSL_SRC_ROOT = "https://www.openssl.org/source/"
ARCH_OPENSSL_COMP = "gz"
ARCH_OPENSSL_EXT = "tar." + ARCH_OPENSSL_COMP
# ROCKSDB_BRANCH = 'v5.10.2'
g_script_path = os.path.realpath(sys.argv[0])


def print_usage():
    print("Usage:\n"
          "[optional] argv[1] platform\n"
          "[optional] argv[2] architecture\n"
          "[optional] argv[3] build system for common (\"ninja\", \"make\", \"gmake\")\n")


def print_message(progress, message):
    print(message.message())
    sys.stdout.flush()


class BuildRequest(object):
    def __init__(self, platform, arch_bit, dir_path):
        platform_or_none = system_info.get_supported_platform_by_name(platform)

        if not platform_or_none:
            raise utils.BuildError('invalid platform')

        arch = platform_or_none.architecture_by_arch_name(arch_bit)
        if not arch:
            raise utils.BuildError('invalid arch')

        build_dir_path = os.path.abspath(dir_path)
        if os.path.exists(build_dir_path):
            shutil.rmtree(build_dir_path)

        os.mkdir(build_dir_path)
        os.chdir(build_dir_path)

        self.build_dir_path_ = build_dir_path

        self.platform_ = platform_or_none.make_platform_by_arch(arch, platform_or_none.package_types())
        print("Build request for platform: {0}, arch: {1} created".format(platform, arch.name()))

    def build_snappy(self, cmake_line, make_install):
        abs_dir_path = self.build_dir_path_
        try:
            cloned_dir = utils.git_clone('https://github.com/fastogt/snappy.git', abs_dir_path)
            os.chdir(cloned_dir)

            os.mkdir('build_cmake_release')
            os.chdir('build_cmake_release')
            snappy_cmake_line = list(cmake_line)
            snappy_cmake_line.append('-DBUILD_SHARED_LIBS=OFF')
            snappy_cmake_line.append('-DSNAPPY_BUILD_TESTS=OFF')
            cmake_policy = run_command.CmakePolicy(print_message)
            make_policy = run_command.CommonPolicy(print_message)
            run_command.run_command_cb(snappy_cmake_line, cmake_policy)
            run_command.run_command_cb(make_install, make_policy)
            os.chdir(abs_dir_path)
        except Exception as ex:
            os.chdir(abs_dir_path)
            raise ex

    def build_libev(self, prefix_path):
        libev_compiler_flags = utils.CompileInfo([], ['--with-pic', '--disable-shared', '--enable-static'])

        pwd = os.getcwd()
        cloned_dir = utils.git_clone('https://github.com/fastogt/libev.git', pwd)
        os.chdir(cloned_dir)

        autogen_policy = run_command.CommonPolicy(print_message)
        autogen_libev = ['sh', 'autogen.sh']
        run_command.run_command_cb(autogen_libev, autogen_policy)

        utils.build_command_configure(libev_compiler_flags, g_script_path, prefix_path)
        os.chdir(pwd)
        shutil.rmtree(cloned_dir)

    def build_common(self, cmake_line, make_install):
        abs_dir_path = self.build_dir_path_
        try:
            cloned_dir = utils.git_clone('https://github.com/fastogt/common.git', abs_dir_path)
            os.chdir(cloned_dir)

            os.mkdir('build_cmake_release')
            os.chdir('build_cmake_release')
            common_cmake_line = list(cmake_line)
            common_cmake_line.append('-DQT_ENABLED=OFF')
            common_cmake_line.append('-DJSON_ENABLED=ON')
            common_cmake_line.append('-DSNAPPY_USE_STATIC=ON')
            cmake_policy = run_command.CmakePolicy(print_message)
            make_policy = run_command.CommonPolicy(print_message)
            run_command.run_command_cb(common_cmake_line, cmake_policy)
            run_command.run_command_cb(make_install, make_policy)
            os.chdir(abs_dir_path)
        except Exception as ex:
            os.chdir(abs_dir_path)
            raise ex

    def build_openssl(self, prefix_path):
        abs_dir_path = self.build_dir_path_
        try:
            openssl_default_version = '1.1.0h'
            compiler_flags = utils.CompileInfo([], ['no-shared'])
            url = '{0}openssl-{1}.{2}'.format(OPENSSL_SRC_ROOT, openssl_default_version, ARCH_OPENSSL_EXT)
            utils.build_from_sources(url, compiler_flags, g_script_path, prefix_path, './config')
        except Exception as ex:
            os.chdir(abs_dir_path)
            raise ex

    def build_jsonc(self, prefix_path):
        abs_dir_path = self.build_dir_path_
        try:
            cloned_dir = utils.git_clone('https://github.com/fastogt/json-c.git', abs_dir_path)
            os.chdir(cloned_dir)

            autogen_policy = run_command.CommonPolicy(print_message)
            autogen_jsonc = ['sh', 'autogen.sh']
            run_command.run_command_cb(autogen_jsonc, autogen_policy)

            configure_jsonc = ['./configure', '--prefix={0}'.format(prefix_path), '--disable-shared',
                               '--enable-static']
            configure_policy = run_command.CommonPolicy(print_message)
            run_command.run_command_cb(configure_jsonc, configure_policy)

            make_jsonc = ['make', 'install']  # FIXME
            make_policy = run_command.CommonPolicy(print_message)
            run_command.run_command_cb(make_jsonc, make_policy)
            os.chdir(abs_dir_path)
        except Exception as ex:
            os.chdir(abs_dir_path)
            raise ex

    def build(self, bs):
        cmake_project_root_abs_path = '..'
        if not os.path.exists(cmake_project_root_abs_path):
            raise utils.BuildError('invalid cmake_project_root_path: %s' % cmake_project_root_abs_path)

        if not bs:
            bs = system_info.SUPPORTED_BUILD_SYSTEMS[0]

        prefix_path = self.platform_.arch().default_install_prefix_path()

        generator = bs.cmake_generator_arg()
        build_system_args = bs.cmd_line()
        # bs_name = bs.name()

        # project static options
        prefix_args = '-DCMAKE_INSTALL_PREFIX={0}'.format(prefix_path)
        cmake_line = ['cmake', cmake_project_root_abs_path, generator, '-DCMAKE_BUILD_TYPE=RELEASE', prefix_args]

        make_install = build_system_args
        make_install.append('install')

        # abs_dir_path = self.build_dir_path_

        self.build_snappy(cmake_line, make_install)
#        self.build_openssl(prefix_path)
        self.build_jsonc(prefix_path)
        self.build_libev(prefix_path)
        self.build_common(cmake_line, make_install)

if __name__ == "__main__":
    argc = len(sys.argv)

    if argc > 1:
        platform_str = sys.argv[1]
    else:
        platform_str = system_info.get_os()

    if argc > 2:
        arch_bit_str = sys.argv[2]
    else:
        arch_bit_str = system_info.get_arch_name()

    if argc > 3:
        bs_str = sys.argv[3]
        args_bs = system_info.get_supported_build_system_by_name(bs_str)
    else:
        args_bs = None

    request = BuildRequest(platform_str, arch_bit_str, 'build_' + platform_str + '_env')
    request.build(args_bs)
