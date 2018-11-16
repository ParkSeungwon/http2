#include"database/mysqldata.h"
#include"framework/bootstrap.h"

class Site : public WebSite
{
public:
	Site();

protected:
	SqlQuery sq;
	void process();

private:
	void index(), db();
};

