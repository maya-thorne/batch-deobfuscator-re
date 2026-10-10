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

@if "%DEBUG%" == "" @echo off
@rem ##########################################################################
@rem
@rem  DiscordBot startup script for Windows
@rem
@rem ##########################################################################

@rem Set local scope for the variables with windows NT shell
if "%OS%"=="Windows_NT" setlocal

set DIRNAME=%~dp0
if "%DIRNAME%" == "" set DIRNAME=.
set APP_BASE_NAME=%~n0
set APP_HOME=%DIRNAME%..

@rem Resolve any "." and ".." in APP_HOME to make it shorter.
for %%i in ("%APP_HOME%") do set APP_HOME=%%~fi

@rem Add default JVM options here. You can also use JAVA_OPTS and DISCORD_BOT_OPTS to pass JVM options to this script.
set DEFAULT_JVM_OPTS=

@rem Find java.exe
if defined JAVA_HOME goto findJavaFromJavaHome

set JAVA_EXE=java.exe
%JAVA_EXE% -version >NUL 2>&1
if "%ERRORLEVEL%" == "0" goto execute

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

set CLASSPATH=%APP_HOME%\lib\DiscordBot.jar;%APP_HOME%\lib\R4J-2.0.7.jar;%APP_HOME%\lib\kord-core-0.8.0-M8.jar;%APP_HOME%\lib\gson-2.8.9.jar;%APP_HOME%\lib\twitch4j-1.6.0.jar;%APP_HOME%\lib\kord-rest-0.8.0-M8.jar;%APP_HOME%\lib\kord-voice-0.8.0-M8.jar;%APP_HOME%\lib\kord-gateway-0.8.0-M8.jar;%APP_HOME%\lib\kord-common-0.8.0-M8.jar;%APP_HOME%\lib\kotlinx-coroutines-test-1.5.2.jar;%APP_HOME%\lib\cache-map-0.3.0.jar;%APP_HOME%\lib\cache-api-0.3.0.jar;%APP_HOME%\lib\kotlinx-coroutines-debug-1.5.2.jar;%APP_HOME%\lib\kotlin-logging-jvm-2.0.11.jar;%APP_HOME%\lib\twitch4j-graphql-1.6.0.jar;%APP_HOME%\lib\apollo-runtime-2.5.11.jar;%APP_HOME%\lib\ktor-client-cio-jvm-1.6.3.jar;%APP_HOME%\lib\ktor-client-serialization-jvm-1.6.3.jar;%APP_HOME%\lib\ktor-client-json-jvm-1.6.3.jar;%APP_HOME%\lib\ktor-client-websockets-jvm-1.6.3.jar;%APP_HOME%\lib\ktor-client-core-jvm-1.6.3.jar;%APP_HOME%\lib\ktor-http-cio-jvm-1.6.3.jar;%APP_HOME%\lib\ktor-network-tls-jvm-1.6.3.jar;%APP_HOME%\lib\ktor-network-jvm-1.6.3.jar;%APP_HOME%\lib\ktor-http-jvm-1.6.3.jar;%APP_HOME%\lib\ktor-utils-jvm-1.6.3.jar;%APP_HOME%\lib\ktor-io-jvm-1.6.3.jar;%APP_HOME%\lib\kotlinx-coroutines-core-jvm-1.5.2.jar;%APP_HOME%\lib\apollo-http-cache-api-2.5.11.jar;%APP_HOME%\lib\apollo-normalized-cache-jvm-2.5.11.jar;%APP_HOME%\lib\apollo-normalized-cache-api-jvm-2.5.11.jar;%APP_HOME%\lib\apollo-api-jvm-2.5.11.jar;%APP_HOME%\lib\kotlin-stdlib-jdk8-1.7.0.jar;%APP_HOME%\lib\twitch4j-chat-1.6.0.jar;%APP_HOME%\lib\twitch4j-pubsub-1.6.0.jar;%APP_HOME%\lib\twitch4j-helix-1.6.0.jar;%APP_HOME%\lib\twitch4j-eventsub-common-1.6.0.jar;%APP_HOME%\lib\twitch4j-extensions-1.6.0.jar;%APP_HOME%\lib\twitch4j-kraken-1.6.0.jar;%APP_HOME%\lib\twitch4j-messaginginterface-1.6.0.jar;%APP_HOME%\lib\twitch4j-common-1.6.0.jar;%APP_HOME%\lib\twitch4j-auth-1.6.0.jar;%APP_HOME%\lib\nv-websocket-client-2.14.jar;%APP_HOME%\lib\events4j-core-0.9.8.jar;%APP_HOME%\lib\events4j-handler-simple-0.9.8.jar;%APP_HOME%\lib\credentialmanager-0.1.2.jar;%APP_HOME%\lib\feign-slf4j-11.7.jar;%APP_HOME%\lib\feign-hystrix-11.7.jar;%APP_HOME%\lib\hystrix-core-1.5.18.jar;%APP_HOME%\lib\events4j-api-0.9.8.jar;%APP_HOME%\lib\archaius-core-0.4.1.jar;%APP_HOME%\lib\slf4j-api-2.0.0-alpha0.jar;%APP_HOME%\lib\feign-okhttp-11.7.jar;%APP_HOME%\lib\okhttp-4.9.2.jar;%APP_HOME%\lib\kotlin-stdlib-jdk7-1.7.0.jar;%APP_HOME%\lib\kotlinx-serialization-json-jvm-1.3.0.jar;%APP_HOME%\lib\atomicfu-jvm-0.16.3.jar;%APP_HOME%\lib\kotlinx-datetime-jvm-0.2.1.jar;%APP_HOME%\lib\kotlinx-serialization-core-jvm-1.3.0.jar;%APP_HOME%\lib\okio-jvm-2.9.0.jar;%APP_HOME%\lib\uuid-jvm-0.2.0.jar;%APP_HOME%\lib\kotlin-stdlib-1.7.0.jar;%APP_HOME%\lib\annotations-23.0.0.jar;%APP_HOME%\lib\caffeine-2.9.2.jar;%APP_HOME%\lib\commons-configuration-1.10.jar;%APP_HOME%\lib\bucket4j-core-4.7.0.jar;%APP_HOME%\lib\feign-jackson-11.7.jar;%APP_HOME%\lib\commons-io-2.11.0.jar;%APP_HOME%\lib\commons-lang3-3.12.0.jar;%APP_HOME%\lib\jackson-datatype-jsr310-2.13.0.jar;%APP_HOME%\lib\jackson-databind-2.13.0.jar;%APP_HOME%\lib\jackson-annotations-2.13.0.jar;%APP_HOME%\lib\jackson-core-2.13.0.jar;%APP_HOME%\lib\checker-qual-3.10.0.jar;%APP_HOME%\lib\error_prone_annotations-2.5.1.jar;%APP_HOME%\lib\commons-lang-2.6.jar;%APP_HOME%\lib\commons-logging-1.1.1.jar;%APP_HOME%\lib\feign-core-11.7.jar;%APP_HOME%\lib\rxjava-1.2.0.jar;%APP_HOME%\lib\HdrHistogram-2.1.9.jar;%APP_HOME%\lib\kotlin-stdlib-common-1.7.0.jar;%APP_HOME%\lib\jna-platform-5.5.0.jar;%APP_HOME%\lib\jna-5.5.0.jar;%APP_HOME%\lib\cache-2.0.2.jar;%APP_HOME%\lib\jsr305-3.0.1.jar


@rem Execute DiscordBot
"%JAVA_EXE%" %DEFAULT_JVM_OPTS% %JAVA_OPTS% %DISCORD_BOT_OPTS%  -classpath "%CLASSPATH%" Main %*

:end
@rem End local scope for the variables with windows NT shell
if "%ERRORLEVEL%"=="0" goto mainEnd

:fail
rem Set variable DISCORD_BOT_EXIT_CONSOLE if you need the _script_ return code instead of
rem the _cmd.exe /c_ return code!
if  not "" == "%DISCORD_BOT_EXIT_CONSOLE%" exit 1
exit /b 1

:mainEnd
if "%OS%"=="Windows_NT" endlocal

:omega
