@'
@echo off
echo Connecting to PostgreSQL database...
echo Database: tinyurl
echo User: tinyurl_user
echo Password: postgres
echo.
"C:\Program Files\PostgreSQL\17\bin\psql.exe" -U tinyurl_user -d tinyurl -h localhost
pause
'@ | Out-File -FilePath "dbshell.bat" -Encoding ASCII