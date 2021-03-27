#!/bin/bash

export $(grep -v '^#' .env | xargs)

echo $DBHost

#host="$DBHost"
#host=`printf "%s:%s" "$host" "$DBPort"`
#echo $host


#until psql -h "$host" -U "postgres" -c '\l'; do
#  >&2 echo "Postgres is unavailable - sleeping"
#  sleep 1
#done
  
#>&2 echo "Postgres is up - executing command"

./wait-for-it.sh -h $DBHost -p 5432 -t 50 -- echo "PostGres Is Up"

sleep 30

./wait-for-it.sh -h $DBHost -p 5432 -t 30 -- echo "PostGres Is Up"

./main
