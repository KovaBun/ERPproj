#DB class
import sqlite3 as sl3

class Database:
    def __init__(self):
       self.con=sl3.Connection("/home/venkat/Documents/AppDB") 
    def insertUser(self, username, password,public_key):
        try:
            sql="insert into users(username,password,public_key) values(?,?,?)"
            self.con.execute(sql,(username,password,public_key))
            self.con.commit()
            return True
        except sl3.IntegrityError:
            return False
    def getUser(self,username,password,public_key):
        sql="select 1 from users where username=? AND password=? AND public_key=?"
        cursor=self.con.execute(sql,(username,password,public_key))
        return cursor.fetchone()
                
        
        

