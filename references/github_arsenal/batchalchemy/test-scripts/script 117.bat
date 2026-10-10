@echo off
echo helloworld rem text8
rem text7
if exist example-file.bat (
  echo The file exists. :: :: if exist file.bat ()
)
if cmdextversion 1 ()
if errorlevel 23234 goto l
echo 'hello world' rem tses
fOr /L %%G IN (1,1,5) DO echo %%G
