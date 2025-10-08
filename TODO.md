# TODO: Migrate Flask App to PostgreSQL for Global Data Availability

## Steps to Complete
- [x] Add psycopg2-binary to requirements.txt
- [x] Update flask_bus_pass_app.py to support PostgreSQL and SQLite
  - [x] Add import os
  - [x] Add DBConnection class
  - [x] Modify get_db_connection to return DBConnection instance
  - [x] Update init_db to use conditional SQL for INSERT (ON CONFLICT for PG, OR IGNORE for SQLite)
  - [x] Update upload_students to use conditional INSERT
  - [x] Update other queries to use %s for PG, ? for SQLite
- [ ] Test locally with SQLite
- [ ] Set up PostgreSQL on Render and deploy
- [ ] Test data sync across systems on Render

## Progress Tracking
- Started: [Date/Time]
- Completed: [Date/Time]
