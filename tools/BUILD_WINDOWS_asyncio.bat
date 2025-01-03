cd ..
pip install -r requirements_asyncio.txt
pyinstaller -F server_asyncio.py -n proxy.exe --noconsole
copy /Y config.json dist\config.json
pause