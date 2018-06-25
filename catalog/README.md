# Project Title

Online Shopping Catalog

## Brief Description

Online Shopping web site includes a lots of categories with a lot of items associated withe each category. Logged in users have the authority to add new items to categorys and also edit them.

### Prerequisites

To have the project work on your machine you need to have a vagrant installed working on a terminal.

### Installing

A step by step series of instructions that tell you how to get the project running

Open the terminal on your PC then,
 
```
vagrant up
```

```
vagrant ssh
```

```
cd /vagrant
```

```
cd catalog
```

```
python application.py
```

then to compile the database file to be imported into the code
```
python app_db.py
```

## Running the application

on any web browser type (localhost:8000) then a web site will open where you will have the ability to login or browse the site as guest

### Application Logic

logged in users have the ability to view all the items in all categories then add new items or remove or edit their added items only.
while guest have the ability to view only all the items in all catrgories.

