import os
import requests
import pandas as pd
from supabase import create_client, Client
uskey="jhweefHFCjhvYjhgcUYFYjygcuf"
apdomain=""
API_URL = 'https://mohcxviiclxxhwbvdzog.supabase.co'
API_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im1vaGN4dmlpY2x4eGh3YnZkem9nIiwicm9sZSI6ImFub24iLCJpYXQiOjE2NzU5MTM5ODgsImV4cCI6MTk5MTQ4OTk4OH0.ahfdv9QG5Pdi2qWh4n4CJ3wMfZiE0bYhWkH_6Fkj2d8'
supabase= create_client(API_URL,API_KEY)
response = supabase.table('api').select("token","domain").execute()
df = pd.DataFrame(response.data)
#print(df)
#print(response)
ind=len(df.index)
tokenval=df['token']
domainval=df['domain']
inittok=tokenval[0]
#print(inittok)
initdomain=domainval[0]
flag=False
for i in range(0,ind):
    if tokenval[i] == uskey:
        flag=True
        apdomain=domainval[i]
if flag==True:
    print("Exists")
    print("Domain : ",apdomain)
else:
    print("INVALID")