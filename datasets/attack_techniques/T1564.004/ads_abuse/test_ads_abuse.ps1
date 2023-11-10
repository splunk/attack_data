#A simple script to test multiple abuse avenues for NTFS alternate data streams.

#Set working location
$DesktopPath = [Environment]::GetFolderPath("Desktop")
Set-Location $DesktopPath

#Delete old test item/create new
$FileName = "test_ads_abuse.txt"
If(Test-Path "$DesktopPath\$FileName"){Remove-Item "$DesktopPath\$FileName"}
$NewFile = New-Item -Path $DesktopPath -Name $FileName

#Set Regular data to text file.
Set-Content $NewFIle -Value "Not empty"

#Write an executable to ADS (calc.exe)
Get-Content C:\Windows\System32\calc.exe -Encoding Byte | Set-Content -Encoding Byte -Stream "Not_Malware.exe" $FileName

# write some encoded powershell to ADS (pop "hello world" message box)
$Text = {Add-Type -AssemblyName PresentationCore,PresentationFramework ; $msgBody = "Hello World" ; $msgTitle = "Hello World" ; $msgButton = 'OK' ; $msgImage = 'Warning' ; $Result = [System.Windows.MessageBox]::Show($msgBody,$msgTitle,$msgButton,$msgImage)}.ToString()
$EncodedText = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($Text))
$EncodedText | Set-Content -Stream "Not_Malware_Code" $FileName

#Open Text File
Try{iex ".\$FileName"}Catch{}

#Open "malware" (Calc.exe)
Try{iex ".\$($FileName):not_malware.exe"}Catch{}

#Execute B64 code from data stream
Try{iex 'powershell.exe -enc $(Get-Content ".\$($FileName)" -Stream "not_malware_code")'}Catch{}

#Open malware (calc.exe) #2
Try{iex 'powershell.exe -command "& {Set-Location $DesktopPath ; .\$($FileName):not_malware.exe}"'}Catch{}