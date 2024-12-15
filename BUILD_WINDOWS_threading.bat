pip install -r requirements.txt
pyinstaller -F server_threading.py -n proxy.exe --noconsole
copy /Y config.json dist\config.json
pause