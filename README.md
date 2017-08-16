# Whole Earth Catalog
 A web application that provides a list of items within a variety of categories and integrate third party user registration and authentication. Authenticated users should have the ability to post, edit, and delete their own items.

##The purpose of some important  files
- ```db_setup.py```  - this file is used to set up  database , contains models.
- ```seed_data.py``` - this file is used to add sample data to the database.
- ```project.py``` - this is the main file that contains the Flask app.


###Using the Vagrant Virtual Machine
- The Vagrant VM has PostgreSQL installed and configured, as well as the psql command line interface (CLI).
- To use the Vagrant virtual machine, clone [fullstack-nanodegree-vm repository ](https://www.google.com/url?q=http://github.com/udacity/fullstack-nanodegree-vm&sa=D&ust=1497404716015000&usg=AFQjCNFZnBD6bB8tuOqowIsXGjhgwp16PA)  navigate to the full-stack-nanodegree-vm/ directory in the terminal, then use the command, then use the command vagrant up (powers on the virtual machine) followed by vagrant ssh (logs into the virtual machine).  
- Remember, once you have executed the vagrant ssh command, you will want to cd /vagrant to change directory to the synced folders in order to work on the project.
- The Vagrant VM provided in the fullstack repo already has Flask , SQLAlchemy installed, so you'll need to have  VM on and be logged into it to run  database configuration file (db_setup.py), and add seed data using ```seed_data.py```.

### Running
After `db_setup.py` and `seed_data.py` file is imported to create database and tables and added seed data.
run the code below to check the test results.
```python
    $ python project.py
```
Then navigate to localhost:8000 on your favorite browser.

##API End Points
- `/category/{category_id}/items/JSON` Display items of a certain category
- `/catalog/JSON` Display All Categories
- `/category/category_id/item/item_id/JSON` Display Item Details