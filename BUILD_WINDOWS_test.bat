pip install -r requirements.txt
pyinstaller -F server.py -n proxy.exe
copy /Y config.json dist\config.json
pause