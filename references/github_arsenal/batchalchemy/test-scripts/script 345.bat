@rem
@rem Copyright 2015 the original author or authors.
@rem
@rem Licensed under the Apache License, Version 2.0 (the "License");
@rem you may not use this file except in compliance with the License.
@rem You may obtain a copy of the License at
@rem
@rem      https://www.apache.org/licenses/LICENSE-2.0
@rem
@rem Unless required by applicable law or agreed to in writing, software
@rem distributed under the License is distributed on an "AS IS" BASIS,
@rem WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
@rem See the License for the specific language governing permissions and
@rem limitations under the License.
@rem

@if "%DEBUG%"=="" @echo off
@rem ##########################################################################
@rem
@rem  core startup script for Windows
@rem
@rem ##########################################################################

@rem Set local scope for the variables with windows NT shell
if "%OS%"=="Windows_NT" setlocal

set DIRNAME=%~dp0
if "%DIRNAME%"=="" set DIRNAME=.
@rem This is normally unused
set APP_BASE_NAME=%~n0
set APP_HOME=%DIRNAME%..

@rem Resolve any "." and ".." in APP_HOME to make it shorter.
for %%i in ("%APP_HOME%") do set APP_HOME=%%~fi

@rem Add default JVM options here. You can also use JAVA_OPTS and CORE_OPTS to pass JVM options to this script.
set DEFAULT_JVM_OPTS=

@rem Find java.exe
if defined JAVA_HOME goto findJavaFromJavaHome

set JAVA_EXE=java.exe
%JAVA_EXE% -version >NUL 2>&1
if %ERRORLEVEL% equ 0 goto execute

echo.
echo ERROR: JAVA_HOME is not set and no 'java' command could be found in your PATH.
echo.
echo Please set the JAVA_HOME variable in your environment to match the
echo location of your Java installation.

goto fail

:findJavaFromJavaHome
set JAVA_HOME=%JAVA_HOME:"=%
set JAVA_EXE=%JAVA_HOME%/bin/java.exe

if exist "%JAVA_EXE%" goto execute

echo.
echo ERROR: JAVA_HOME is set to an invalid directory: %JAVA_HOME%
echo.
echo Please set the JAVA_HOME variable in your environment to match the
echo location of your Java installation.

goto fail

:execute
@rem Setup the command line

set CLASSPATH=%APP_HOME%\lib\DistantHorizons-core-2.0.0-a-dev-1.20.2.jar;%APP_HOME%\lib\DistantHorizons-api-2.0.0-a-dev-1.20.2.jar;%APP_HOME%\lib\lz4-java-1.8.0.jar;%APP_HOME%\lib\sqlite-jdbc-3.43.0.0.jar;%APP_HOME%\lib\toml-3.6.6.jar;%APP_HOME%\lib\json-3.6.6.jar;%APP_HOME%\lib\lwjgl-jawt-3.2.3.jar;%APP_HOME%\lib\log4j-core-2.20.0.jar;%APP_HOME%\lib\log4j-api-2.20.0.jar;%APP_HOME%\lib\joml-1.10.2.jar;%APP_HOME%\lib\junit-jupiter-engine-5.8.2.jar;%APP_HOME%\lib\junit-jupiter-params-5.8.2.jar;%APP_HOME%\lib\junit-jupiter-api-5.8.2.jar;%APP_HOME%\lib\junit-platform-engine-1.8.2.jar;%APP_HOME%\lib\junit-platform-commons-1.8.2.jar;%APP_HOME%\lib\junit-jupiter-5.8.2.jar;%APP_HOME%\lib\junit-4.13.jar;%APP_HOME%\lib\lwjgl-assimp-3.2.3.jar;%APP_HOME%\lib\lwjgl-assimp-3.2.3-natives-windows.jar;%APP_HOME%\lib\lwjgl-glfw-3.2.3.jar;%APP_HOME%\lib\lwjgl-glfw-3.2.3-natives-windows.jar;%APP_HOME%\lib\lwjgl-openal-3.2.3.jar;%APP_HOME%\lib\lwjgl-openal-3.2.3-natives-windows.jar;%APP_HOME%\lib\lwjgl-opengl-3.2.3.jar;%APP_HOME%\lib\lwjgl-opengl-3.2.3-natives-windows.jar;%APP_HOME%\lib\lwjgl-stb-3.2.3.jar;%APP_HOME%\lib\lwjgl-stb-3.2.3-natives-windows.jar;%APP_HOME%\lib\lwjgl-tinyfd-3.2.3.jar;%APP_HOME%\lib\lwjgl-tinyfd-3.2.3-natives-windows.jar;%APP_HOME%\lib\lwjgl-3.2.3.jar;%APP_HOME%\lib\lwjgl-3.2.3-natives-windows.jar;%APP_HOME%\lib\annotations-16.0.2.jar;%APP_HOME%\lib\guava-31.1-jre.jar;%APP_HOME%\lib\jsr305-3.0.2.jar;%APP_HOME%\lib\google-collect-0.5.jar;%APP_HOME%\lib\fastutil-8.5.11.jar;%APP_HOME%\lib\core-3.6.6.jar;%APP_HOME%\lib\hamcrest-core-1.3.jar;%APP_HOME%\lib\failureaccess-1.0.1.jar;%APP_HOME%\lib\listenablefuture-9999.0-empty-to-avoid-conflict-with-guava.jar;%APP_HOME%\lib\checker-qual-3.12.0.jar;%APP_HOME%\lib\error_prone_annotations-2.11.0.jar;%APP_HOME%\lib\j2objc-annotations-1.3.jar;%APP_HOME%\lib\opentest4j-1.2.0.jar


@rem Execute core
"%JAVA_EXE%" %DEFAULT_JVM_OPTS% %JAVA_OPTS% %CORE_OPTS%  -classpath "%CLASSPATH%" com.seibel.distanthorizons.core.jar.JarMain %*

:end
@rem End local scope for the variables with windows NT shell
if %ERRORLEVEL% equ 0 goto mainEnd

:fail
rem Set variable CORE_EXIT_CONSOLE if you need the _script_ return code instead of
rem the _cmd.exe /c_ return code!
set EXIT_CODE=%ERRORLEVEL%
if %EXIT_CODE% equ 0 set EXIT_CODE=1
if not ""=="%CORE_EXIT_CONSOLE%" exit %EXIT_CODE%
exit /b %EXIT_CODE%

:mainEnd
if "%OS%"=="Windows_NT" endlocal

:omega
