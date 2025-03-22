
for port in 80 443 4848 8080 8443 12174; do
  echo "Testant le port $port..."
  curl -s -o /dev/null -w "%{http_code}" http://env-5978560-odoo-01.hidora.com:$port/web
  echo " - /web"
  curl -s -o /dev/null -w "%{http_code}" http://env-5978560-odoo-01.hidora.com:$port/web/database/selector
  echo " - /web/database/selector"
  curl -s -o /dev/null -w "%{http_code}" http://env-5978560-odoo-01.hidora.com:$port/web/login
  echo " - /web/login"
done
