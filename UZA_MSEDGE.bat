@echo off
taskkill /f /t /im chrome.exe
start "" "C:\Users\Dev C\AppData\Local\Chromium\Application\chrome.exe" --guest --proxy-server=127.0.0.1:2500 https://www.pixiv.net https://liaoyuan1949.site https://liaoyuan1949.site