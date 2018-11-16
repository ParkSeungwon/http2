#pragma once
#include<vector>
#include<sstream>
#include<json/json.h>
#include<type_traits>
#include"mysqlquery.h"

class SqlQuery : public Mysqlquery, public Json::Value
{
public:
	SqlQuery() = default;
	SqlQuery(const SqlQuery& r);
	int select(std::string table, std::string where = "");
	bool insert(int n);
	bool insert(std::vector<std::string> v);
	template<class T1, class... T2> bool insert(T1 a, T2... b)
	{
		if(std::is_same<std::string, T1>::value ||
				std::is_same<const char*, T1>::value) query_ << "'"  << a << "',";
		else query_ << a << ",";
		if constexpr(!sizeof...(b)) {
			std::string q = "insert into " + table_name + " values (" + query_.str();
			q.back() = ')';
			q += ";";
			query_.clear();
			return myQuery(q);
		} else return insert(b...);
	}
	void group_by(std::vector<std::string> v);
	
	std::string encrypt(std::string pass);
	std::vector<std::string> show_tables();
	std::string now();//system clock->mysql datetime string

protected:
	struct Column {
		std::string name;
		unsigned size;
		std::string type;
	};
	std::string table_name;
	std::vector<Column> columns;

private:
	bool is_int(int nth_column);
	bool is_real(int nth_column);
	std::stringstream query_;
};

