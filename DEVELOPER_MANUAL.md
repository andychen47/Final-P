Developer Manual  

Project Overview  
The URL Threat Scanner is a web-based application that analyzes a website URLs for potential security threats. It checks URLs against phishing data and generates reports to check the site for any potential malcious activites.

System Architecture  
The project uses a client and server structure. The frontend is built with HTML, CSS, and JavaScript. The backend is built with Node.js and connects to a Supabase database. External services such as PhishStats and URLScan.io are used to analyze URLs.

Requirements  
Node.js 
npm  
A Supabase account  
A URLScan.io API key  

Installation  
Download or clone the project repository.  
Open a terminal in the project folder.  
Run the following command to install dependencies:  
npm install  

Environment Setup  
Modify the  file named .env in the project root and add the following values:

SUPABASE_URL=your_supabase_project_url  
SUPABASE_KEY=your_supabase_anon_public_key  
URLSCAN_API_KEY=your_urlscan_api_key  
PORT=3000  

Database Setup  
Create a table named scan_history in Supabase.  
The table should include id, url, result, and created_at columns.  
Row Level Security should be disabled or configured to allow inserts and reads.

Running the Application  
Start the backend server by running:  
npm start  

The server will run at http://127.0.0.1:3000  
Open scan.html in a web browser to use the application.

Verifying Results  
Scan results can be viewed in the scan_history table in Supabase.  
Results can also be checked by visiting http://127.0.0.1:3000/test-db.
