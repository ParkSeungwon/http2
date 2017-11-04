#include"mysqldata.h"
#include"bootstrap.h"

class DnDD : public BootStrapServer
{
public:
	DnDD();

protected:
	SqlQuery sq;
	void process();

private:
	void signin(), index(), search(), mn(), pg(), edit(), add(), new_book(), comment(), vote();
	std::string search(std::string s), field(std::string s);
	std::array<int, 5> allowlevel(std::string table, std::string book);
	std::vector<std::string> tables();
	int maxpage(std::string table, std::string book);
	std::string id, level, name, db, table, book, page;
	std::vector<std::string> tmp;
	std::array<int, 5> allow;
};

