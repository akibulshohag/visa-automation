# Visa Automation Node.js

This project is a Node.js conversion of the IVAC appointment Tampermonkey script.
It supports running multiple accounts concurrently, rotating proxies on IP blocks, and solving Captchas using Capmonster.

## Setup

1. Make sure you have Node.js and MySQL installed.
2. Run `npm install` to install dependencies.
3. Configure the `.env` file with your MySQL database credentials and Capmonster API key (`CAPMONSTER_KEY`).
   - Leave `DB_NAME` as `visa_automation` or set it to what you prefer. The script will create the database and tables automatically on the first run.

## Usage

1. Start the script once to initialize the database:
   ```bash
   node index.js
   ```
2. Insert your accounts and proxy links into the MySQL database tables `accounts` and `proxies`.
   - The script expects a phone and password in the `accounts` table.
   - You can map multiple proxies to a single account in the `proxies` table (`account_id` references the `accounts.id`).
3. Run the script again:
   ```bash
   node index.js
   ```

The script will launch concurrent workers for every active account in the DB.
