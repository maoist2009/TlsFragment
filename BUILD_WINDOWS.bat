pyinstaller -F server.py -n proxy.exe --noconsole
copy /Y config.json dist\config.json
pause