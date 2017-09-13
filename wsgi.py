import sys

sys.path.insert(0, '/var/www/catalog')

from item_catalog import app

app.secret_key = 'New secret key. Change it on server'
app.config['SQLALCHEMY_DATABASE_URI'] = (
    'postgresql://'
    'catalog:password@localhost/catalog')
