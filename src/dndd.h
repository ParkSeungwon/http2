#include"mysqldata.h"
#include"htmlserver.h"

class Dndd : public HTMLServer 
{
public:
	Dndd();

protected:
	SqlQuery sq;
	virtual void process();

private:
	void login(), signin(), upload(), index(), if_logged(), search();
	std::string id, password, level, name;
};
