$FileContent = Get-Content -Path "obfuscated.cmd" # Get Malicious batch script content
$DynamicVariable1 = "" # This is the dynamic variable value of assign in the first line in batch script, copy the value of first line variable to here!!!
$DynamicVariable2 = ""
$DynamicVariable3 = ""
$DynamicVariable4 = ""
foreach($Line in $FileContent){ #Iterate each line of Batch
    $Matches = ""
    $Matches = [regex]::Matches($Line, '%(.*?)%') #If contains dynamic variable
    for ($i = 0; $i -lt $Matches.Count; $i++) {
        if( $Matches[$i].Value -like "*:*" -and $Matches[$i].Value -like "*~*" ){#If contains dynamic variable character selection
            $IndexOfTildeSign = $Matches[$i].Value.IndexOf("~")
            $IndexOfCommaSign = $Matches[$i].Value.IndexOf(",")
            $MainMatch = $Matches[$i].Value.SubString(1,($IndexOfTildeSign-2))
            if( $MainMatch -like "DynamicVariable1" ){ #If it gets a character from DynamicVariable1
                $IndexForDynamicVariable = $Matches[$i].Value.SubString($IndexOfTildeSign+1 , ($IndexOfCommaSign - $IndexOfTildeSign - 1))
                $ReplaceCharacter = $DynamicVariable1[$IndexForDynamicVariable]
            }
            elseif( $MainMatch -like "DynamicVariable2" ){ #If it gets a character from DynamicVariable2
                $IndexForDynamicVariable = $Matches[$i].Value.SubString($IndexOfTildeSign+1 , ($IndexOfCommaSign - $IndexOfTildeSign - 1))
                $ReplaceCharacter = $DynamicVariable2[$IndexForDynamicVariable]
            }
            elseif( $MainMatch -like "DynamicVariable3" ){ #If it gets a character from DynamicVariable3
                $IndexForDynamicVariable = $Matches[$i].Value.SubString($IndexOfTildeSign+1 , ($IndexOfCommaSign - $IndexOfTildeSign - 1))
                $ReplaceCharacter = $DynamicVariable3[$IndexForDynamicVariable]
            }
            elseif( $MainMatch -like "DynamicVariable4" ){ #If it gets a character from DynamicVariable4
                $IndexForDynamicVariable = $Matches[$i].Value.SubString($IndexOfTildeSign+1 , ($IndexOfCommaSign - $IndexOfTildeSign - 1))
                $ReplaceCharacter = $DynamicVariable4[$IndexForDynamicVariable]
            }
            $Line = $Line -replace [regex]::Escape($Matches[$i].Value), $ReplaceCharacter #Replace Dynamic data exchange with new character that got from variable
        }
        else{ #If doesn't contains dynamic variable character selection
            $Line = $Line -replace [regex]::Escape($Matches[$i].Value),""
        } 
    }
    #After remove Dynamic data exchange from each line 
    #check if line contains "set" keyword, because if there is a "set" command
    #we need to update our dynamic variables
    if( $Line -like "*set*" ){ 
        $IndexOfDoubleQuoteSign = $Line.IndexOf('"')
        $IndexOfEqualSign = $Line.IndexOf("=")
        $DynamicVariableNameInLine = $Line.SubString($IndexOfDoubleQuoteSign + 1 , ($IndexOfEqualSign - $IndexOfDoubleQuoteSign - 1) )
        $NewDynamicVariableValues = $Line.Substring($IndexOfEqualSign + 1 , ($Line.Length - $IndexOfEqualSign - 2))
        if ( $DynamicVariableNameInLine -eq "DynamicVariable1"){ #If "set" command change/assign DynamicVariable1
            $DynamicVariable1 = $NewDynamicVariableValues
            Write-Host "New DynamicVariable1 variables => $($NewDynamicVariableValues)" -ForegroundColor Green
        }
        elseif ( $DynamicVariableNameInLine -eq "DynamicVariable2" ){ #If "set" command change/assign DynamicVariable2
            $DynamicVariable2 = $NewDynamicVariableValues
            Write-Host "New DynamicVariable2 variables => $($NewDynamicVariableValues)" -ForegroundColor Green
        }
        elseif ( $DynamicVariableNameInLine -eq "DynamicVariable3" ){ #If "set" command change/assign DynamicVariable3
            $DynamicVariable3 = $NewDynamicVariableValues
            Write-Host "New DynamicVariable3 variables => $($NewDynamicVariableValues)" -ForegroundColor Green
        }
        elseif ( $DynamicVariableNameInLine -eq "DynamicVariable4" ){ #If "set" command change/assign DynamicVariable4
            $DynamicVariable4 = $NewDynamicVariableValues
            Write-Host "New DynamicVariable4 variables => $($NewDynamicVariableValues)" -ForegroundColor Green
        }
    }
    Write-Host $Line -ForegroundColor Red #Write the de-obfuscated new line
}
