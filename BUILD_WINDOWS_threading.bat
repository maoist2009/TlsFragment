pip install -r requirements_threading.py.txt
pyinstaller -F server_threading.py -n proxy.exe --noconsole
copy /Y config.json dist\config.json
pause