.\smi.exe eject -p "Risk of Rain 2" -a "E:\Programmieren\C#\RiskOfRain2Hack\RiskOfRain2Hack\bin\Debug\RiskOfRain2Hack.dll" -n RiskOfRain2Hack -c Loader -m load


$path = "F:\Programme\Steam\steamapps\common\Risk of Rain 2\Risk of Rain 2_Data\Managed\Assembly-CSharp.dll"
[Reflection.Assembly]::ReflectionOnlyLoadFrom($path).CustomAttributes |
Where-Object {$_.AttributeType.Name -eq "TargetFrameworkAttribute" } | 
Select-Object -ExpandProperty ConstructorArguments | 
Select-Object -ExpandProperty value