#pragma once
#include<vector>
#include<json/json.h>
#include"mysqlquery.h"

class SqlQuery : public Mysqlquery, public Json::Value
{
public:
	int select(std::string table, std::string where = "");
	bool insert(int n);
	bool insert(std::vector<std::string> v);
	void group_by(std::vector<std::string> v);
	
	std::string encrypt(std::string pass);
	std::vector<std::string> show_tables();
	std::string now();//system clock->mysql datetime string

	struct Column {
		std::string name;
		unsigned size;
		std::string type;
	};
	std::vector<Column>& desc() {
		return columns;
	}

protected:
	std::string table_name;
	std::vector<Column> columns;

private:
	bool is_int(int nth_column);
	bool is_real(int nth_column);
};

