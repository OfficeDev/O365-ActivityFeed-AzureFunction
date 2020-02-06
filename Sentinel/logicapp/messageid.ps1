using namespace System.Net

# Input bindings are passed in via param block.
param($Request, $TriggerMetadata)

$name = "email"

#This code uses a regex pattern that identifies the MessageID in the message body.
if ($name) {
    $status = [HttpStatusCode]::OK

    $regex = "(?:<(?:(?:[a-zA-Z0-9!#$%&\*+/=?^_`{|}~-]+(?:\.[a-zA-Z0-9!#$%&\*+/=?^_{|}~-]+)*)|(?:(?:(?:[\x01-\x08\x0B\x0C\x0E-\x1F\x7F]|[\x21\x23-\x5B\x5D-\x7E])|(?:\\[\x01-\x09\x0B\x0C\x0E-\x7F]))*))@(?:(?:[a-zA-Z0-9!#$%&\*+/=?^_{|}~-]+(?:\.[a-zA-Z0-9!#$%&\'*+/=?^_`{|}~-]+)*)|(?:\[(?:(?:[\x01-\x08\x0B\x0C\x0E-\x1F\x7F]|[\x21-\x5A\x5E-\x7E])|(?:\\[\x01-\x09\x0B\x0C\x0E-\x7F]))*\]))>)"
    $request.body.emailbody -match $regex

$body = [string]::Format($Matches.Values)
$body

            }

else {
    $status = [HttpStatusCode]::BadRequest
    $body = "Please pass a name on the query string or in the request body."
     }


# Associate values to output bindings by calling 'Push-OutputBinding'.
Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
    StatusCode = $status
    Body = $body
})
