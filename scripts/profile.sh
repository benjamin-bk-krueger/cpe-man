# Python venv
export PATH=~/venv/bin:$PATH

# Default credentials, need to be changed on production stage
export POSTGRES_URL=localhost:5432
export POSTGRES_USER=cpeman
export POSTGRES_PW=cpeman
export POSTGRES_DB=cpeman
export SECRET_KEY=secret-key-goes-here
export FLASK_ENV=production
export FLASK_DEBUG=0
export S3_ENDPOINT=http://localhost:9000
export S3_FOLDER=http://localhost:9000/cpeman-public
export S3_QUOTA=100
export BUCKET_PUBLIC=cpeman-public
export BUCKET_PRIVATE=cpeman-private
export WWW_SERVER=http://localhost:5010
export MAIL_ENABLE=1
export MAIL_SERVER=localhost
export MAIL_SENDER=mail@localhost
export MAIL_ADMIN=admin@localhost
export APP_VERSION=0.1
export APP_PREFIX=
export LOG_ENABLE=0
export LOG_FILE=cpeman.log