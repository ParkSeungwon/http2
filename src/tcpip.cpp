#include<iostream>
#include<sstream>
#include<string>
#include<cstring>
#include"server.h"
#include"htmlserver.h"
#include"util.h"
using namespace std;

class Dndd : public HTMLServer {
public:
protected:
	virtual void process() {
		content_.replace(content_.find("사나이"), 6, "Man");
	}
} f;

int main(int ac, char** av)
{
	int port = ac < 2 ? 2001 : atoi(av[1]);
	Server sv{port};
	sv.start(f);
}
