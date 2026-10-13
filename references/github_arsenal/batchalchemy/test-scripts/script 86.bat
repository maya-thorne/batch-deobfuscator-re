@ECHO OFF
if [C:\ProgramData\ZeroTier\One\zerotier-one_x64.exe] == [] (
	 -i %*
) else (
	C:\ProgramData\ZeroTier\One\zerotier-one_x64.exe -i %*
)
