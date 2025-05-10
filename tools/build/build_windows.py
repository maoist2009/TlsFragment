import os
import sys
import shutil

script_dir = os.path.dirname(__file__)
root_app_dir = os.path.abspath(script_dir + '/../..')
os.chdir(root_app_dir)

BUILD_DIR = root_app_dir + '/build/windows'

try:
  os.makedirs(BUILD_DIR)
except FileExistsError:
  pass

commands = f'''
python -m venv venv
venv\\Scripts\\activate.bat

python -m pip install --upgrade pip
python -m pip install -r {script_dir}/requirements.txt -r {script_dir}/requirements_build_windows.txt

echo Remove PyInstaller's dist directory if exists.
rm -rf dist

python -m PyInstaller --clean {script_dir}/helloworld.windows.onefile.spec
'''

import subprocess
for cmd in commands.split('\n'):
  if cmd in ('', '\n'):
    continue
  print(f'running cmd : {cmd}')
  subprocess.run(cmd.split(' '))

  

# sanity check
package = f'{root_app_dir}/dist/helloworld.exe'


if os.path.exists(package):
  print(f"Successfully built {package}")
  #include_arch(arch.arch)
  #include_version(version.version)
else:
  subprocess.run(['tree'])
  raise('Failed to build package...')