@ECHO OFF

::----------------------------------------------------------------------
:: IntelliJ IDEA startup script.
::----------------------------------------------------------------------

:: ---------------------------------------------------------------------
:: Ensure IDE_HOME points to the directory where the IDE is installed.
:: ---------------------------------------------------------------------
SET "IDE_BIN_DIR=%~dp0"
FOR /F "delims=" %%i in ("%IDE_BIN_DIR%\..") DO SET "IDE_HOME=%%~fi"

:: ---------------------------------------------------------------------
:: Locate a JRE installation directory which will be used to run the IDE.
:: Try (in order): IDEA_JDK, idea64.exe.jdk, ..\jbr, JDK_HOME, JAVA_HOME.
:: ---------------------------------------------------------------------
SET JRE=

IF NOT "%IDEA_JDK%" == "" (
  IF EXIST "%IDEA_JDK%" SET "JRE=%IDEA_JDK%"
)

SET _JRE_CANDIDATE=
IF "%JRE%" == "" IF EXIST "%APPDATA%\JetBrains\IntelliJIdea2022.3\idea64.exe.jdk" (
  SET /P _JRE_CANDIDATE=<"%APPDATA%\JetBrains\IntelliJIdea2022.3\idea64.exe.jdk"
)
IF "%JRE%" == "" (
  IF NOT "%_JRE_CANDIDATE%" == "" IF EXIST "%_JRE_CANDIDATE%" SET "JRE=%_JRE_CANDIDATE%"
)

IF "%JRE%" == "" (
  IF "%PROCESSOR_ARCHITECTURE%" == "AMD64" IF EXIST "%IDE_HOME%\jbr" SET "JRE=%IDE_HOME%\jbr"
  IF "%PROCESSOR_ARCHITECTURE%" == "ARM64" IF EXIST "%IDE_HOME%\jbr" SET "JRE=%IDE_HOME%\jbr"
)

IF "%JRE%" == "" (
  IF EXIST "%JDK_HOME%" (
    SET "JRE=%JDK_HOME%"
  ) ELSE IF EXIST "%JAVA_HOME%" (
    SET "JRE=%JAVA_HOME%"
  )
)

SET "JAVA_EXE=%JRE%\bin\java.exe"
IF NOT EXIST "%JAVA_EXE%" (
  ECHO ERROR: cannot start IntelliJ IDEA.
  ECHO No JRE found. Please make sure IDEA_JDK, JDK_HOME, or JAVA_HOME point to a valid JRE installation.
  EXIT /B
)

:: ---------------------------------------------------------------------
:: Collect JVM options and properties.
:: ---------------------------------------------------------------------
IF NOT "%IDEA_PROPERTIES%" == "" SET IDE_PROPERTIES_PROPERTY="-Didea.properties.file=%IDEA_PROPERTIES%"

SET VM_OPTIONS_FILE=
SET USER_VM_OPTIONS_FILE=
IF NOT "%IDEA_VM_OPTIONS%" == "" (
  :: 1. %<IDE_NAME>_VM_OPTIONS%
  IF EXIST "%IDEA_VM_OPTIONS%" SET "VM_OPTIONS_FILE=%IDEA_VM_OPTIONS%"
)
IF "%VM_OPTIONS_FILE%" == "" (
  :: 2. <IDE_HOME>\bin\[win\]<exe_name>.vmoptions ...
  IF EXIST "%IDE_BIN_DIR%\idea64.exe.vmoptions" (
    SET "VM_OPTIONS_FILE=%IDE_BIN_DIR%\idea64.exe.vmoptions"
  ) ELSE IF EXIST "%IDE_BIN_DIR%\win\idea64.exe.vmoptions" (
    SET "VM_OPTIONS_FILE=%IDE_BIN_DIR%\win\idea64.exe.vmoptions"
  )
  :: ... [+ <IDE_HOME>.vmoptions (Toolbox) || <config_directory>\<exe_name>.vmoptions]
  IF EXIST "%IDE_HOME%.vmoptions" (
    SET "USER_VM_OPTIONS_FILE=%IDE_HOME%.vmoptions"
  ) ELSE IF EXIST "%APPDATA%\JetBrains\IntelliJIdea2022.3\idea64.exe.vmoptions" (
    SET "USER_VM_OPTIONS_FILE=%APPDATA%\JetBrains\IntelliJIdea2022.3\idea64.exe.vmoptions"
  )
)

SET ACC=
SET USER_GC=
IF NOT "%USER_VM_OPTIONS_FILE%" == "" (
  SET ACC="-Djb.vmOptionsFile=%USER_VM_OPTIONS_FILE%"
  FINDSTR /R /C:"-XX:\+.*GC" "%USER_VM_OPTIONS_FILE%" > NUL
  IF NOT ERRORLEVEL 1 SET USER_GC=yes
) ELSE IF NOT "%VM_OPTIONS_FILE%" == "" (
  SET ACC="-Djb.vmOptionsFile=%VM_OPTIONS_FILE%"
)
IF NOT "%VM_OPTIONS_FILE%" == "" (
  IF "%USER_GC%" == "" (
    FOR /F "eol=# usebackq delims=" %%i IN ("%VM_OPTIONS_FILE%") DO CALL SET "ACC=%%ACC%% %%i"
  ) ELSE (
    FOR /F "eol=# usebackq delims=" %%i IN (`FINDSTR /R /V /C:"-XX:\+Use.*GC" "%VM_OPTIONS_FILE%"`) DO CALL SET "ACC=%%ACC%% %%i"
  )
)
IF NOT "%USER_VM_OPTIONS_FILE%" == "" (
  FOR /F "eol=# usebackq delims=" %%i IN ("%USER_VM_OPTIONS_FILE%") DO CALL SET "ACC=%%ACC%% %%i"
)
IF "%VM_OPTIONS_FILE%%USER_VM_OPTIONS_FILE%" == "" (
  ECHO ERROR: cannot find a VM options file
)

SET "CLASS_PATH=%IDE_HOME%\lib\util.jar"
SET "CLASS_PATH=%CLASS_PATH%;%IDE_HOME%\lib\app.jar"
SET "CLASS_PATH=%CLASS_PATH%;%IDE_HOME%\lib\3rd-party-rt.jar"
SET "CLASS_PATH=%CLASS_PATH%;%IDE_HOME%\lib\platform-statistics-devkit.jar"
SET "CLASS_PATH=%CLASS_PATH%;%IDE_HOME%\lib\jps-model.jar"
SET "CLASS_PATH=%CLASS_PATH%;%IDE_HOME%\lib\stats.jar"
SET "CLASS_PATH=%CLASS_PATH%;%IDE_HOME%\lib\protobuf.jar"
SET "CLASS_PATH=%CLASS_PATH%;%IDE_HOME%\lib\external-system-rt.jar"
SET "CLASS_PATH=%CLASS_PATH%;%IDE_HOME%\lib\forms_rt.jar"
SET "CLASS_PATH=%CLASS_PATH%;%IDE_HOME%\lib\intellij-test-discovery.jar"
SET "CLASS_PATH=%CLASS_PATH%;%IDE_HOME%\lib\annotations.jar"
SET "CLASS_PATH=%CLASS_PATH%;%IDE_HOME%\lib\groovy.jar"
SET "CLASS_PATH=%CLASS_PATH%;%IDE_HOME%\lib\3rd-party-native.jar"
SET "CLASS_PATH=%CLASS_PATH%;%IDE_HOME%\lib\annotations-java5.jar"
SET "CLASS_PATH=%CLASS_PATH%;%IDE_HOME%\lib\async-profiler-windows.jar"
SET "CLASS_PATH=%CLASS_PATH%;%IDE_HOME%\lib\async-profiler.jar"
SET "CLASS_PATH=%CLASS_PATH%;%IDE_HOME%\lib\byte-buddy-agent.jar"
SET "CLASS_PATH=%CLASS_PATH%;%IDE_HOME%\lib\error-prone-annotations.jar"
SET "CLASS_PATH=%CLASS_PATH%;%IDE_HOME%\lib\externalProcess-rt.jar"
SET "CLASS_PATH=%CLASS_PATH%;%IDE_HOME%\lib\idea_rt.jar"
SET "CLASS_PATH=%CLASS_PATH%;%IDE_HOME%\lib\intellij-coverage-agent-1.0.682.jar"
SET "CLASS_PATH=%CLASS_PATH%;%IDE_HOME%\lib\jsch-agent.jar"
SET "CLASS_PATH=%CLASS_PATH%;%IDE_HOME%\lib\jsp-base.jar"
SET "CLASS_PATH=%CLASS_PATH%;%IDE_HOME%\lib\junit.jar"
SET "CLASS_PATH=%CLASS_PATH%;%IDE_HOME%\lib\junit4.jar"
SET "CLASS_PATH=%CLASS_PATH%;%IDE_HOME%\lib\platform-objectSerializer-annotations.jar"
SET "CLASS_PATH=%CLASS_PATH%;%IDE_HOME%\lib\rd.jar"
SET "CLASS_PATH=%CLASS_PATH%;%IDE_HOME%\lib\tools-testsBootstrap.jar"
SET "CLASS_PATH=%CLASS_PATH%;%IDE_HOME%\lib\util_rt.jar"
SET "CLASS_PATH=%CLASS_PATH%;%IDE_HOME%\lib\ant/lib/ant.jar"

:: ---------------------------------------------------------------------
:: Run the IDE.
:: ---------------------------------------------------------------------
"%JAVA_EXE%" ^
  -cp "%CLASS_PATH%" ^
  %ACC% ^
  "-XX:ErrorFile=%USERPROFILE%\java_error_in_idea_%%p.log" ^
  "-XX:HeapDumpPath=%USERPROFILE%\java_error_in_idea.hprof" ^
  %IDE_PROPERTIES_PROPERTY% ^
  -Djava.system.class.loader=com.intellij.util.lang.PathClassLoader -Didea.vendor.name=JetBrains -Didea.paths.selector=IntelliJIdea2022.3 "-Djna.boot.library.path=%IDE_HOME%/lib/jna/amd64" "-Dpty4j.preferred.native.folder=%IDE_HOME%/lib/pty4j" -Djna.nosys=true -Djna.noclasspath=true -Dsplash=true --add-opens=java.base/java.io=ALL-UNNAMED --add-opens=java.base/java.lang=ALL-UNNAMED --add-opens=java.base/java.lang.ref=ALL-UNNAMED --add-opens=java.base/java.lang.reflect=ALL-UNNAMED --add-opens=java.base/java.net=ALL-UNNAMED --add-opens=java.base/java.nio=ALL-UNNAMED --add-opens=java.base/java.nio.charset=ALL-UNNAMED --add-opens=java.base/java.text=ALL-UNNAMED --add-opens=java.base/java.time=ALL-UNNAMED --add-opens=java.base/java.util=ALL-UNNAMED --add-opens=java.base/java.util.concurrent=ALL-UNNAMED --add-opens=java.base/java.util.concurrent.atomic=ALL-UNNAMED --add-opens=java.base/jdk.internal.vm=ALL-UNNAMED --add-opens=java.base/sun.nio.ch=ALL-UNNAMED --add-opens=java.base/sun.nio.fs=ALL-UNNAMED --add-opens=java.base/sun.security.ssl=ALL-UNNAMED --add-opens=java.base/sun.security.util=ALL-UNNAMED --add-opens=java.desktop/java.awt=ALL-UNNAMED --add-opens=java.desktop/java.awt.dnd.peer=ALL-UNNAMED --add-opens=java.desktop/java.awt.event=ALL-UNNAMED --add-opens=java.desktop/java.awt.image=ALL-UNNAMED --add-opens=java.desktop/java.awt.peer=ALL-UNNAMED --add-opens=java.desktop/java.awt.font=ALL-UNNAMED --add-opens=java.desktop/javax.swing=ALL-UNNAMED --add-opens=java.desktop/javax.swing.plaf.basic=ALL-UNNAMED --add-opens=java.desktop/javax.swing.text.html=ALL-UNNAMED --add-opens=java.desktop/sun.awt.datatransfer=ALL-UNNAMED --add-opens=java.desktop/sun.awt.image=ALL-UNNAMED --add-opens=java.desktop/sun.awt.windows=ALL-UNNAMED --add-opens=java.desktop/sun.awt=ALL-UNNAMED --add-opens=java.desktop/sun.font=ALL-UNNAMED --add-opens=java.desktop/sun.java2d=ALL-UNNAMED --add-opens=java.desktop/sun.swing=ALL-UNNAMED --add-opens=jdk.attach/sun.tools.attach=ALL-UNNAMED --add-opens=jdk.compiler/com.sun.tools.javac.api=ALL-UNNAMED --add-opens=jdk.internal.jvmstat/sun.jvmstat.monitor=ALL-UNNAMED --add-opens=jdk.jdi/com.sun.tools.jdi=ALL-UNNAMED ^
  com.intellij.idea.Main ^
  %*
