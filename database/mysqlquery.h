#pragma once
#include <string>
#include <cppconn/connection.h>
#include <cppconn/driver.h>
#include <cppconn/resultset.h>

class Mysqlquery 
{
private:
    sql::Driver *driver;
    sql::Connection *con;
    sql::Statement *stmt;

protected:
	sql::ResultSet *res;
    bool myQuery(std::string str);

public:
    bool connect(std::string host, std::string user, std::string pass, std::string db);
    void connect(Mysqlquery& copy);
    Mysqlquery();
	virtual ~Mysqlquery();
};

/*Tclass
class Tcls
{
public:
	static string table_name;
	static unordered_map<string name, string type> structure;
	string contents[];
}
*/

