#!/bin/env sh
RETRIES=10
export PGPASSWORD=$POSTGRES_PASSWORD

until psql -h $POSTGRES_HOST -U $POSTGRES_USER -d $POSTGRES_DB -c "select 1" > /dev/null 2>&1 || [ "$RETRIES" -eq 0 ]; do
  RETRIES=$((RETRIES - 1))
  echo "Waiting for postgres server, $RETRIES remaining attempts..."
  sleep 3
done
