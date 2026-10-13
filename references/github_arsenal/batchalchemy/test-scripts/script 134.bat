rmdir .\AramChecker /s /q
del AramChecker.rar
call mvn clean package
jpackage --name AramChecker --input target --main-jar AramChecker.jar --main-class eu.time.aramchecker.AramChecker --type app-image --win-console --resource-dir res
copy start.bat AramChecker
winrar.exe a AramChecker.rar .\AramChecker