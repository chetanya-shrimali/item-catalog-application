# item-catalog-application
Item-catalog-application is a advanced project based on `Flask Framework` which. It includes following features
- Back-end based on `Flask` and Front-end on mainly in `Bootstrap`
- Used databse from `SQL Alchemy`
- Sign in using third party application particularly `GOOGLE`
- User can log in using third party and add categories and subcategories
- Features to edit and delete the catalog items for logged in users
- Subcatalog items under the catalog items with features to edit and delete for logged in users
### Requirements
- For requirements refer to requirements.txt
  To install type the following command before the respective\
  `pip install <reqirement-name>`
- In order to download the project hit the green button on top-right
### How to run
 - In order to run the application follow these steps in sequence
    - Run database_setup.py\
    `python database_setup.py`
    - Run data.py\
    `python data.py`
    - Run item_catalog.py\
    `python item_catalog.py`
    - Open the browser and use following address to explore!!\
    `http://localhost:8000/category`
    `http://localhost:8000/category/new`
    `http://localhost:8000/category/<integer>/subcategory`
    `http://localhost:8000/category/<integer>/subcategory/new`
    `http://localhost:8000/category/<integer1>/subcategory/<integer2>/edit`
    `http://localhost:8000/category/<integer1>/subcategory/<integer2>/delete`
    `http://localhost:8000/categories/subcategories/json`
    `http://localhost:8000/categories/json`
    `http://localhost:8000/categories/<int:cat_id>/subcategories/json`
    `http://localhost:8000/categories/<int:cat_id>/subcategories/<int:sub_id>/json`
