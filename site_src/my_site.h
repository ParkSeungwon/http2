#include"database/mysqldata.h"
#include"framework/website.h"

class Site : public WebSite
{
public:
	Site();

protected:
	SqlQuery sq;
	void process();

private:
	void index(), upload();
};

