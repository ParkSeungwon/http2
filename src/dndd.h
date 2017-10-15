#include"mysqldata.h"
#include"htmlserver.h"

class Dndd : public HTMLServer 
{
public:
	Dndd();
	std::string id, password, level, name;

protected:
	SqlQuery sq;
	virtual void process();

private:
	void login(), signin(), upload(), index();
};
