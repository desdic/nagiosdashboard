/usr/bin/uwsgi --uid=nginx -p 8 -s /tmp/uwsgi.sock --daemonize=/var/log/uwsgi/nagiosdashboard.log -w app:app --chdir=/var/www/nagiosdashboard  --pidfile /tmp/nagiosdashboard.pid
