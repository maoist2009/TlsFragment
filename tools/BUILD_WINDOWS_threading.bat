cd ..
pip install -r requirements_threading.txt
pyinstaller -F server_threading.py -n proxy.exe --noconsole
copy /Y config.json dist\config.json
pause