ipAddress=$(hostname -I | cut -d ' ' -f1 | sed -e 's/ //')
cd web
source .venv/bin/activate
sudo screen -S ReconftwWebserver -X kill
sudo screen -dmS ReconftwWebserver python3 manage.py runserver $ipAddress:8001
sudo service redis-server start
sudo screen -S ReconftwCelery -X kill
sudo screen -dmS ReconftwCelery python3 -m celery -A web worker -l info -P prefork -Q run_scans,default
