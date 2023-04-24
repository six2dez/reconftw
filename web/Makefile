setup:			## Setup
	rm db.sqlite3 dump.rdb celerybeat-schedule.db -rf
	rm static/img/target_icon/* -f
	python3 manage.py makemigrations
	python3 manage.py migrate

up:				## Start
	eval "$(redis-server)"
	eval "$(python3.9 -m celery -A web worker -l info -P solo)"
	python3 manage.py runserver 0.0.0.0:8000

user:		## Generate Username
	python3 manage.py createsuperuser
