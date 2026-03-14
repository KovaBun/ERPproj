#DB class
import sqlite3 as sl3

class Database:
    def __init__(self):
       self.con=sl3.Connection("/home/venkat/Documents/AppDB") 
    def insertUser(self, username, password):
        try:
            sql="insert into users(username,password) values(?,?)"
            self.con.execute(sql,(username,password))
            self.con.commit()
            return True
        except sl3.IntegrityError:
            return False
    def getUser(self,username,password):
        sql="select 1 from users where username=? AND password=?"
        cursor=self.con.execute(sql,(username,password))
        return cursor.fetchone()
                
        
        

