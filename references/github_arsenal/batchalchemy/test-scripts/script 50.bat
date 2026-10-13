@echo off
setlocal
set QT_DEVICE_PIXEL_RATIO=2
"%~dp0googleearth.exe" %*
endlocal
