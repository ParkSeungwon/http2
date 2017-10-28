#include"mysqldata.h"
#include"bootstrap.h"

class DnDD : public BootStrapServer
{
public:
	DnDD();

protected:
	SqlQuery sq;
	virtual void process();

private:
	void login(), signin(), upload(), index(), if_logged(), search(), mn(), pg();
	std::string id, level, name, db, table, book, page;
	std::string search(std::string s), field(std::string s), quote_encode(std::string);
	std::vector<std::string> tables();
	int maxpage(std::string table, std::string book);
};

