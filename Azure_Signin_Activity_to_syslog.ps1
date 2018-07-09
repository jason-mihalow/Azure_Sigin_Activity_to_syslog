<#
Created by: Jason Mihalow

Description:
This script is meant to send the Azure signin activity logs to a SIEM via syslog.  Since Active Directory in Azure is a distributed cloud service, the logs arive to the API destination out of order.  This is because not all systems have the same load or are in the same part of the world.  Since this is the case, we need to rely on comparing the id field from the logs in chunks of time and sending the difference to the SIEM.  There is also an alert built in to detect when the logs have drifted beyond a configurable amount of time from the current time.  This could indicate an issue with the Azure service such as a login attack.  Detailed information regarding this script can be found:

https://www.sans.org/reading-room/whitepapers/logging/building-custom-siem-integration-api-based-log-source-azure-ad-graph-sign-in-events-38280

Variables that need to be configured:
$ClientID
$ClientSecret
$tenantdomain
$dstserver
$dstport

Schedule this script to execute using the local task scheduler.  You will want to tune the frequency at which the script is executed.  The time it takes to execute one run should not be longer than the execution frequency.  The time it takes to execute the script one time will vary depending on the amount of risk alerts you have in your portal.  You can adjust $query_minutes to impact the amount of time one execution of the script takes.  Less $query_minutes = less ids to compare = shorter execution.  The results of each query should overlap to catch and logs arriving late in the Microsoft logging facility.
#>

# This script will require the Web Application and permissions setup in Azure Active Directory
$ClientID       = "" # Should be a ~35 character string insert your info here
$ClientSecret   = "" # Should be a ~44 character string insert your info here
$loginURL       = "https://login.microsoftonline.com/"
$tenantdomain   = "" # For example, contoso.onmicrosoft.com
$resource       = "https://graph.windows.net"

#this is the current time in UTC timezone
$universaltime_current = (get-date).ToUniversalTime()

#assign the amount of minute behind the current you want to start with
$query_minutes = -360

#put the total amount of time being used into a format the API service will accept
$querytime = "{0:s}" -f  (((get-date).AddMinutes($query_minutes)).ToUniversalTime()) + "Z"

#destination logging server
$dstserver = ""

#destination TCP port
$dstport = ""

#get the current path
$current_path = convert-path .

#create TCP socket connection to logging server using .NET
$tcpConnection = New-Object System.Net.Sockets.TcpClient($dstserver, $dstport)
$tcpStream = $tcpConnection.GetStream()
$writer = New-Object System.IO.StreamWriter($tcpStream)
$writer.AutoFlush = $true

# Get an Oauth 2 access token based on client id, secret and tenant domain
$body       = @{grant_type="client_credentials";resource=$resource;client_id=$ClientID;client_secret=$ClientSecret}
$oauth      = Invoke-RestMethod -Method Post -Uri $loginURL/$tenantdomain/oauth2/token?api-version=1.0 -Body $body

if ($oauth.access_token -ne $null) 
{
    $headerParams = @{'Authorization'="$($oauth.token_type) $($oauth.access_token)"}

    #the url creation for the Windows Graph API along with our time frame delimitor    
    $url = "https://graph.windows.net/$tenantdomain/activities/signinEvents?api-version=beta&`$filter=signinDateTime ge $querytime"
    
    #initialize array that will hold the results from the API query
    $myReport = @()

    #initialize array that will hold all of the timestamps from logs of the current query
    $DateTimeReport = @()

    #initialize array to hold ids values from the last execution of the script
    $lastrun_ids = @()
	
	$test_path = $current_path + "\current_ids.txt"
	
    #test if a file exists with all the ids that were in $myReport from the last run
    if ($test_path)
    {
        #assign all the ids from the last run file to a variable
        $lastrun_ids = Get-Content $test_path 

        #delete the existing last run file of ids 
        remove-item -Path $test_path
    }
    
    #pagination - process each page of results  
    do
    {
        #set the error flag to makes sure we only proceed when we have positive results
        $errorflag = $true
        
        #loop to get the next page of results
        do
        {
            #try to get the next page of results
            try
            {
                #query the API and assign the results to $myReport; skip to catch if we get an error results
                $myReport = (Invoke-WebRequest -UseBasicParsing -Headers $headerParams -Uri $url)
                
                #if we are here then we didn't get an error; set the errorflag to $false so we can exit the loop
                $errorflag = $false 
                
                #need to test if the results were empty; initialize the array $emptytest
                $emptytest = @()

                #assign all the values in $myReport.Content to the array $emptytest
                $emptytest = (($myReport.Content | convertfrom-json).value)
                
                #there was no content in the current query; increase the querytime and alert the SIEM
                if (!$emptytest[0])
                {
                    #send special syslog message to SIEM; API query results were empty; either a Microsoft API issue or a throttling issue.
                    $line= "WARNING: API query had zero results.  Drift may be larger than query period"
                    $writer.WriteLine($line)
    
                    <#
                    #This section tries to auto adjust the query time until we get results.  This runs the risk of duplication of logs in favor of having the most complete record.

                    #step back a half hour from the current query time
                    $query_minutes = $query_minutes - 30
                    
                    #tell the SIEM about the adjustment
                    $line = "WARNING: Increasing the query minutes by 30; query_minues are now at $query_minutes"
                    $writer.WriteLine($line)

                    #set the querytime to use the new amount of minutes
                    $querytime = "{0:s}" -f  (((get-date).AddMinutes($query_minutes)).ToUniversalTime()) + "Z"

                    #set $url to be queried again with the new querytime
                    $url = "https://graph.windows.net/$tenantdomain/activities/signinEvents?api-version=beta&`$filter=signinDateTime ge $querytime"
                    
                    #set $errorflag to true so we don't exit the loop and we try the query again
                    $errorflag = $true

                    #>
                }      
            }
            #catch any error from the previous API query (Invoke-WebRequest) so we don't crash
            catch
            {
                #print the error to the screen
                $Error

                #sleep for 5 seconds and try the query again
                Start-Sleep -s 5
            }

        }while($errorflag -eq $true)

        
        #if there are ids from a previous execution
        if ($lastrun_ids)
        {
            #loop through each log in the page of results which exists in $myReport.Content
            foreach ($event in (($myReport.Content | ConvertFrom-Json).value))
            {
                #put the event timestamp from the current lgo in the $DateTimeReport array
                [array]$DateTimeReport += $event.signinDateTime
                
                #send the event id to the new ids file
                $event.id | Out-File -Append -NoClobber -FilePath $test_path
                        
                #test if the current id is in the list of ids from the previous execution
                $current_id = $event.id
                $unique = $lastrun_ids -notcontains "$current_id"
                   
                #if the event was not in the list from the previous execution
                if ($unique)
                {
                    #assign $line to the compressed json
                    $line = ($event | Convertto-Json -Compress)

                    #send $line to the SIEM view TCP
                    $writer.Writeline($line)
                }
              
            }  
        }

        #there was not a file with the IDs from the previous execution
        else
        {
            #loop through each log in the page of results which exists in $myReport.Content 
            foreach ($event in (($myReport.Content | ConvertFrom-Json).value))
            {
                #put the event timestamp from the current lgo in the $DateTimeReport array
                [array]$DateTimeReport += $event.signinDateTime
                
                #send the event id to the new ids file
                $event.id | Out-File -Append -NoClobber -FilePath $test_path
        
                #assign $line to the compressed json
                $line = ($event | Convertto-Json -Compress)

                #send $line to the SIEM view TCP
                $writer.Writeline($line)
            }
        }
        #update the $url variable with the URL of the next page of query results
        $url = ($myReport.Content | ConvertFrom-Json).'@odata.nextLink'
   
    } while($url -ne $null)

#sort the DateTimeReport decending
$DateTimeReport = $DateTimeReport | sort -Descending
                
#the top array value is the latest timestamp; assign to timestamp type variable
[datetime]$latest_stamp = $DateTimeReport[0]
 
#find the differce in time between the latest_stamp and the current time; assign it to a variable
$diff = New-TimeSpan -Start $latest_stamp.ToUniversalTime() -End $universaltime_current

#test to write the current API drift to the screen
#write-output ($diff | select Hours,Minutes,Seconds)

#if the time differnce is greater than 45 minutes
if ((($diff.Minutes) -gt 45) -or (($diff.Hours) -ge 1))
{
    #send special syslog message to SIEM warning of the API drift
    $line= "WARNING: API Logs are " + ($diff | select Days,Hours,Minutes,Seconds) +" behind the current time."
    $writer.writeline($line)
} 

#close the TCP socket with the SIEM
$writer.Close()
$tcpConnection.Close()

}
#we failed to obtain an access token
else 
{
    #let SIEM know we are having issues with the API authentication
    $line = "WARNING: API authentication issue.  We were unable to obtain an OAUTH token.  Check API key validity."
    $writer.WriteLine($line)   
}

