@ECHO OFF
if [C:\ProgramData\ZeroTier\One\zerotier-one_x64.exe] == [] (
	 -q %*
) else (
	C:\ProgramData\ZeroTier\One\zerotier-one_x64.exe -q %*
)
