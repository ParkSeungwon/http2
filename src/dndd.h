#include"mysqldata.h"
#include"htmlserver.h"

class DnDD : public HTMLServer 
{
public:
	DnDD();

protected:
	SqlQuery sq;
	virtual void process();

private:
	void login(), signin(), upload(), index(), if_logged(), search();
	std::string id, password, level, name, db, table, book, page;
};

