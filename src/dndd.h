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
	void login(), signin(), upload(), index(), if_logged(), search(), mn();
	std::string id, level, name, db, table, book, page;
};

