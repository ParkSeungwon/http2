#include <iostream>
#include <stdexcept>
#include <cppconn/exception.h>
#include <cppconn/statement.h>
#include <cppconn/prepared_statement.h>
#include "mysqlquery.h"
using namespace std;

bool Mysqlquery::myQuery(std::string str)
{
	//cout << str << endl;
    bool ok = false;
	try {
        //cout << "Executing query....." << endl << endl;
        res = stmt->executeQuery(str);
		//cout << "Done." << endl;
        ok = true;
	} catch (sql::SQLException &e) {
		if(e.getErrorCode() != 0) {
			cout << "# ERR: SQLException in " << __FILE__ ;
			cout << "(" << __FUNCTION__<< ") on line " << __LINE__  << endl;
			cout << "# ERR: " << e.what();
			cout << "  (MySQL error code: " << e.getErrorCode();
			cout << ", SQLState: " << e.getSQLState() << " )"  << endl << endl;
		}
	}
    return ok;
}

bool Mysqlquery::connect(string host, string user, string pass, string db)
{
    bool ok = false;
    try {
        //cout << "Connecting database to " << host << endl << endl;
        driver = get_driver_instance();
        con = driver->connect(host, user, pass);
        con->setSchema(db);
        stmt = con->createStatement();
        //std::cout << "done.." << std::endl;
        ok = true;
    } catch (sql::SQLException &e) {
		cout << "# ERR: SQLException in " << __FILE__ ;
		cout << "(" << __FUNCTION__<< ") on line " << __LINE__  << endl;
		cout << "# ERR: " << e.what();
		cout << "  (MySQL error code: " << e.getErrorCode();
		cout << ", SQLState: " << e.getSQLState() << " )"  << endl << endl;
	}
    return ok;
}

void Mysqlquery::connect(Mysqlquery& copy)
{
	driver = copy.driver;
	con = copy.con;
	stmt = copy.stmt;
	res = copy.res;
}

Mysqlquery::Mysqlquery()
{
    con = NULL;
    stmt = NULL;
    res = NULL;
}

Mysqlquery::~Mysqlquery()
{
//    if(con != NULL) delete con;
//    if(stmt != NULL) delete stmt;
//    if(res != NULL) delete res;
}
