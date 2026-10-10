@echo off

::We don't want people running this in the wrong place
IF NOT EXIST ".\hl2.exe" (
	ECHO Game binary doesn't exist. Are you executing this script from the wrong directory?
	EXIT /B 1
)

::Give the user fair warning
ECHO This script will attempt to reset Garry's Mod to its default state. If the game is running, it will be closed.
ECHO You will lose any settings that have been changed and potentially any saved data, such as duplications.
ECHO Addons will not be removed.
ECHO.

::Let the user bail
CHOICE /N /M "Are you sure you want to continue? [Y/N]"

IF ERRORLEVEL == 2 (
	ECHO Aborting.
	EXIT /B 1
)

ECHO.

::Some of the below won't work if the game is already running
TASKKILL /f /im "hl2.exe" >NUL 2>&1

::Config files
ECHO [1/7] Removing configuration
CALL :DEL_DIR ".\garrysmod\cfg"
CALL :DEL_DIR ".\garrysmod\settings"

::Addon data
ECHO [2/7] Removing stored addon data
CALL :DEL_DIR ".\garrysmod\data"

::Server downloads
ECHO [3/7] Removing downloaded server content
CALL :DEL_DIR ".\garrysmod\download"
CALL :DEL_DIR ".\garrysmod\downloads"
CALL :DEL_DIR ".\garrysmod\downloadlists"

::Gamemodes/Lua
ECHO [4/7] Removing base Lua scripts and gamemodes
CALL :DEL_DIR ".\garrysmod\gamemodes\base"
CALL :DEL_DIR ".\garrysmod\gamemodes\sandbox"
CALL :DEL_DIR ".\garrysmod\gamemodes\terrortown"
CALL :DEL_DIR ".\garrysmod\lua"

::SQLite databases
ECHO [5/7] Removing SQLite databases
CALL :DEL_FILE ".\garrysmod\cl.db"
CALL :DEL_FILE ".\garrysmod\sv.db"
CALL :DEL_FILE ".\garrysmod\mn.db"

::Lua/Workshop cache
ECHO [6/7] Emptying Lua/Workshop cache
CALL :DEL_DIR ".\garrysmod\cache"

::Get steam to redownload anything we've just deleted (this actually also deletes cfg/config.cfg from the Steam Cloud)
ECHO [7/7] Marking game's content for validation by Steam
.\hl2.exe -factoryresetstuff

ECHO.
ECHO Finished. Steam will attempt to download some missing files the next time you launch Garry's Mod.
ECHO.

PAUSE
EXIT /B

:DEL_DIR
    ::ECHO Removing dir %1.
    IF EXIST %1 ( RMDIR /S /Q %1 )
    GOTO:EOF

:DEL_FILE
    ::ECHO Removing file %1.
    IF EXIST %1 ( DEL /Q %1 )
    GOTO:EOF